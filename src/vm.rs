use crate::util_imports::*;
use core::str::Utf8Error;

new_key_type! {
    pub struct HeapKey;
}

use crate::{ast::Type, opcodes::varint::decode_varint};

use super::opcodes::*;
extern crate alloc;
use alloc::vec::Vec;
use slotmap::{HopSlotMap, SlotMap, new_key_type};
use smol_str::SmolStr;

#[derive(Clone, Debug)]
pub struct Function {
    bytecode: Vec<u8>,
    name: Option<SmolStr>,
    arg_count: usize,
    args_types: Vec<Type>,
}

#[derive(Clone, Debug)]
pub struct Class {
    name: SmolStr,
    field_types: HashMap<SmolStr, Type>,
    field_indices: HashMap<SmolStr, usize>,
    method_indices: HashMap<SmolStr, usize>,
    methods: Vec<Function>,
}

#[derive(Clone, Debug)]
pub struct StackFrame {
    stack_start: usize,
    start_end: usize,
    function_idx: usize,
    ip: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    I64(i64),
    F64(f64),
    Bool(bool),
    String(SmolStr),
    HashMap(HeapKey),
    Array(HeapKey),
    Tuple(HeapKey),
    Custom(HeapKey),
    Upvalue(HeapKey),
    Null,
    // TODO
    Closure,
}

impl Value {
    fn type_description(&self) -> &'static str {
        match self {
            Value::I64(_) => "i64",
            Value::F64(_) => "f64",
            Value::Bool(_) => "bool",
            Value::String(_) => "string",
            Value::HashMap(_) => "HashMap",
            Value::Array(_) => "Array",
            Value::Tuple(_) => "Tuple",
            Value::Custom(_) => todo!(),
            Value::Upvalue(_) => todo!(),
            Value::Null => "null",
            Value::Closure => "closure",
        }
    }
    fn is_upvalue(&self) -> bool {
        matches!(self, Self::Upvalue(_))
    }
    fn upvalue_fetch(&self, heap: &HopSlotMap<HeapKey, Value>) -> Value {
        match self {
            Value::Upvalue(heap_key) => heap
                .get(*heap_key)
                .expect("If heap key exists on stack, it should exist on heap")
                .clone(),
            otherval => {
                panic!("upvalue_fetch called on non-upvalue: {otherval:?}");
            }
        }
    }
    fn upvalue_replace(&mut self, heap: &HopSlotMap<HeapKey, Value>) {
        if self.is_upvalue() {
            let val = self.upvalue_fetch(heap);
            core::mem::replace(self, val);
        }
    }
}

#[derive(Clone, Debug)]
struct BytecodeStorage {
    functions: Vec<Function>,
    global: Vec<u8>,
    class_decl: Vec<Class>,
}

#[derive(Clone, Debug)]
pub struct Vm {
    bytecode_storage: BytecodeStorage,
    stack: Vec<Value>,
    stack_frames: Vec<StackFrame>,
    globals: HashMap<Vec<u8>, Value>,
    heap: HopSlotMap<HeapKey, Value>,
    local_stack_start: usize,
    func: Option<usize>,
    ip: usize,
}

#[derive(Clone, Debug)]
pub struct Bytecode {
    bytecode: Vec<u8>,
    classes: Vec<Class>,
    functions: Vec<Function>,
}

#[derive(Clone, Debug)]
pub enum VmError {
    InvalidInstruction(u8),
    EndOfBytecode(Option<usize>, usize),
    NonExistentFunctionIndex(usize),
    NonExistentGlobal(Vec<u8>),
    RedeclaredGlobal(Vec<u8>),
    InvalidUtf8String(Vec<u8>, Utf8Error),
    TypeCastError(&'static str, &'static str),
    InvalidTypesForBinaryOpcode(&'static str, Opcode, &'static str),
    InvalidTypesForUnaryOpcode(&'static str, Opcode),
    StackUnderflow,
    OutOfBoundsOfStackFrame,
    DivisionByZero,
    ModuloByZero,
}

impl BytecodeStorage {
    fn parse_opcode(&self, func: Option<usize>, ip: &mut usize) -> Result<Opcode, VmError> {
        let n = self
            .get_slice(func, ip)?
            .first()
            .ok_or(VmError::EndOfBytecode(func, *ip))?;
        let res = Opcode::parse_u8(*n).ok_or(VmError::InvalidInstruction(*n));
        *ip += res.is_ok() as bool as usize;
        res
    }
    fn get_bytecode(&self, func: Option<usize>) -> Result<&[u8], VmError> {
        Ok(match func {
            Some(n) => {
                &self
                    .functions
                    .get(n)
                    .ok_or(VmError::NonExistentFunctionIndex(n))?
                    .bytecode
            }
            None => &self.global,
        })
    }
    fn get_slice(&self, func: Option<usize>, ip: &mut usize) -> Result<&[u8], VmError> {
        let bytecode = self.get_bytecode(func)?;
        let slice = bytecode
            .get(*ip..)
            .ok_or(VmError::EndOfBytecode(func, *ip))?;
        Ok(slice)
    }
    fn parse_varint(&self, func: Option<usize>, ip: &mut usize) -> Result<u64, VmError> {
        let (varint, size) =
            decode_varint(self.get_slice(func, ip)?).ok_or(VmError::EndOfBytecode(func, *ip))?;
        *ip += size;
        Ok(varint)
    }
    fn parse_slice<'a>(
        &'a self,
        len: usize,
        func: Option<usize>,
        ip: &mut usize,
    ) -> Result<&'a [u8], VmError> {
        let slice = self.get_slice(func, ip)?;
        if let Some(slice) = slice.get(..len) {
            *ip += len;
            return Ok(slice);
        }
        Err(VmError::EndOfBytecode(func, *ip))
    }
}

impl Vm {
    fn stack_pop(&mut self) -> Result<Value, VmError> {
        if self.stack.len() <= self.local_stack_start {
            return Err(VmError::StackUnderflow);
        }
        Ok(self.stack.pop().expect("Checked above"))
    }
    fn stack_slice(&mut self) -> &mut [Value] {
        self.stack
            .get_mut(self.local_stack_start..)
            .expect("Local stack start should always be > 0")
    }
    fn stack_store(&mut self, idx: usize, val: Value) -> Result<(), VmError> {
        let place = self
            .stack
            .get_mut(self.local_stack_start + idx)
            .ok_or(VmError::StackUnderflow)?;
        *place = val;
        Ok(())
    }
    fn stack_load(&mut self, idx: usize) -> Result<Value, VmError> {
        let place = self
            .stack
            .get(self.local_stack_start + idx)
            .ok_or(VmError::StackUnderflow)?;
        Ok(place.clone())
    }
    fn stack_push(&mut self, value: Value) {
        self.stack.push(value)
    }
}

impl Vm {
    fn parse_opcode(&mut self) -> Result<Opcode, VmError> {
        self.bytecode_storage.parse_opcode(self.func, &mut self.ip)
    }
    fn parse_varint(&mut self) -> Result<usize, VmError> {
        self.bytecode_storage
            .parse_varint(self.func, &mut self.ip)
            .map(|n| {
                // If on other architectures, the encode should make sure we don't encode anything larger than usize
                n.try_into().unwrap()
            })
    }
    fn run(&mut self, bytecode: &Bytecode) -> Result<(), VmError> {
        self.handle_bytecode_classes(bytecode);
        self.handle_bytecode_functions(bytecode);
        self.bytecode_storage.global.clear();
        self.bytecode_storage.global.extend(&bytecode.bytecode);
        loop {
            let opcode = self.parse_opcode()?;
            match opcode {
                Opcode::LOAD_GLOBAL => {
                    let len = self.parse_varint()?;
                    let slice = self
                        .bytecode_storage
                        .parse_slice(len, self.func, &mut self.ip)?;
                    let global = self
                        .globals
                        .get(slice)
                        .ok_or(VmError::NonExistentGlobal(slice.to_owned()))?
                        .clone();
                    self.stack.push(global);
                }
                Opcode::STORE_GLOBAL => {
                    let len = self.parse_varint()?;
                    let popped = self.stack_pop()?;
                    let slice = self
                        .bytecode_storage
                        .parse_slice(len, self.func, &mut self.ip)?;
                    *self
                        .globals
                        .get_mut(slice)
                        .ok_or(VmError::NonExistentGlobal(slice.to_owned()))? = popped;
                }
                Opcode::DEFINE_GLOBAL => {
                    let len = self.parse_varint()?;
                    let slice = self
                        .bytecode_storage
                        .parse_slice(len, self.func, &mut self.ip)?;
                    if self.globals.contains_key(slice) {
                        return Err(VmError::RedeclaredGlobal(slice.to_owned()));
                    }
                    self.globals.insert(slice.to_owned(), Value::Null);
                }
                Opcode::PUSH_NULL => self.stack.push(Value::Null),
                Opcode::PUSH_TRUE => self.stack.push(Value::Bool(true)),
                Opcode::PUSH_FALSE => self.stack.push(Value::Bool(false)),
                Opcode::PUSH_I64 => {
                    let num = self.parse_varint()?;
                    self.stack.push(Value::I64(num as i64));
                }
                Opcode::PUSH_F64 => {
                    let num = self.parse_varint()?;
                    self.stack.push(Value::F64(num as f64));
                }
                Opcode::PUSH_STR => {
                    let len = self.parse_varint()?;
                    let slice = self
                        .bytecode_storage
                        .parse_slice(len, self.func, &mut self.ip)?;
                    let str = str::from_utf8(slice)
                        .map_err(|e| VmError::InvalidUtf8String(slice.to_owned(), e))?;

                    let string = SmolStr::from(str);
                    self.stack.push(Value::String(string))
                }
                Opcode::STORE => {
                    let idx = self.parse_varint()?;
                    let top = self.stack_pop()?;
                    self.stack_store(idx, top)?;
                }
                Opcode::LOAD => {
                    let idx = self.parse_varint()?;
                    let val = self.stack_load(idx)?;
                    self.stack.push(val);
                }
                Opcode::POP => {
                    self.stack.pop();
                }
                Opcode::DUP => {
                    let popped = self.stack_pop()?;
                    self.stack.push(popped.clone());
                    self.stack.push(popped)
                }
                Opcode::SWAP => {
                    let first = self.stack_pop()?;
                    let second = self.stack_pop()?;
                    self.stack.push(first);
                    self.stack.push(second);
                }
                Opcode::MAKE_UPVALUE => {
                    let idx = self.parse_varint()?;
                    let val = self.stack_load(idx)?;
                    match val {
                        Value::HashMap(_)
                        | Value::Array(_)
                        | Value::Tuple(_)
                        | Value::Custom(_)
                        | Value::Upvalue(_) => {}
                        _other => {
                            // Allocate value on heap,
                            // store new "ptr" to heap in stack
                            todo!()
                        }
                    }
                }
                Opcode::ADD => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64(a + b),
                        (Value::F64(a), Value::F64(b)) => Value::F64(a + b),
                        (Value::String(s1), Value::String(s2)) => Value::String({
                            let mut string = String::new();
                            string.push_str(&s1);
                            string.push_str(&s2);
                            SmolStr::from(string)
                        }),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::SUB => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64(b - a),
                        (Value::F64(a), Value::F64(b)) => Value::F64(b - a),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::MUL => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64(a * b),
                        (Value::F64(a), Value::F64(b)) => Value::F64(a * b),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::DIV => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => match b.checked_div(a) {
                            Some(v) => Value::I64(v),
                            None => return Err(VmError::DivisionByZero),
                        },
                        (Value::F64(a), Value::F64(b)) => Value::F64(b / a),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::MOD => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => match b.checked_rem(a) {
                            Some(v) => Value::I64(v),
                            None => return Err(VmError::ModuloByZero),
                        },
                        (Value::F64(a), Value::F64(b)) => Value::F64(b % a),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::NEG => {
                    let mut val = self.stack_pop()?;
                    val.upvalue_replace(&self.heap);
                    let res = match val {
                        Value::I64(a) => Value::I64(-a),
                        Value::F64(a) => Value::F64(-a),
                        other1 => {
                            return Err(VmError::InvalidTypesForUnaryOpcode(
                                other1.type_description(),
                                opcode,
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::UNARY_PLUS => {
                    let mut val = self.stack_pop()?;
                    val.upvalue_replace(&self.heap);
                    let res = match val {
                        val @ (Value::I64(_) | Value::F64(_)) => val,
                        other1 => {
                            return Err(VmError::InvalidTypesForUnaryOpcode(
                                other1.type_description(),
                                opcode,
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::EQ => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    // Implement equality between values & do this
                    todo!();
                    // self.stack.push(res);
                }
                Opcode::NEQ => {
                    // Opposite of EQ
                    todo!()
                }
                Opcode::GT => todo!(),
                Opcode::LT => todo!(),
                Opcode::GTE => todo!(),
                Opcode::LTE => todo!(),
                Opcode::NOT => {
                    let mut val = self.stack_pop()?;
                    val.upvalue_replace(&self.heap);
                    let res = match val {
                        Value::Bool(a) => Value::Bool(!a),
                        other1 => {
                            return Err(VmError::InvalidTypesForUnaryOpcode(
                                other1.type_description(),
                                opcode,
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::AND => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(a && b),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::OR => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(a || b),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::XOR => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(a ^ b),
                        (Value::I64(a), Value::I64(b)) => Value::I64(a ^ b),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::BITNOT => {
                    let mut val = self.stack_pop()?;
                    val.upvalue_replace(&self.heap);
                    let res = match val {
                        Value::I64(a) => Value::I64(!a),
                        other1 => {
                            return Err(VmError::InvalidTypesForUnaryOpcode(
                                other1.type_description(),
                                opcode,
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::BITAND => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64(a & b),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::BITOR => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64(a | b),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::SHL => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64(b << a),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::SHR => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64(b >> a),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::SHR_UNSIGNED => {
                    let mut first = self.stack_pop()?;
                    first.upvalue_replace(&self.heap);
                    let mut second = self.stack_pop()?;
                    second.upvalue_replace(&self.heap);
                    let res = match (first, second) {
                        (Value::I64(a), Value::I64(b)) => Value::I64((b as u64 >> a) as i64),
                        (other1, other2) => {
                            return Err(VmError::InvalidTypesForBinaryOpcode(
                                other1.type_description(),
                                opcode,
                                other2.type_description(),
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::INC => {
                    let mut val = self.stack_pop()?;
                    val.upvalue_replace(&self.heap);
                    let res = match val {
                        Value::I64(a) => Value::I64(a + 1),
                        other1 => {
                            return Err(VmError::InvalidTypesForUnaryOpcode(
                                other1.type_description(),
                                opcode,
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::DEC => {
                    let mut val = self.stack_pop()?;
                    val.upvalue_replace(&self.heap);
                    let res = match val {
                        Value::I64(a) => Value::I64(a - 1),
                        other1 => {
                            return Err(VmError::InvalidTypesForUnaryOpcode(
                                other1.type_description(),
                                opcode,
                            ));
                        }
                    };
                    self.stack.push(res);
                }
                Opcode::JMP => todo!(),
                Opcode::JMP_ABSOLUTE => todo!(),
                Opcode::JMP_IF_TRUE => todo!(),
                Opcode::JMP_IF_FALSE => todo!(),
                Opcode::MAKE_ARRAY => todo!(),
                Opcode::MAKE_TUPLE => todo!(),
                Opcode::MAKE_MAP => todo!(),
                Opcode::INDEX => todo!(),
                Opcode::SET_INDEX => todo!(),
                Opcode::LEN => todo!(),
                Opcode::CALL => todo!(),
                Opcode::RET => todo!(),
                Opcode::ACCESS_FIELD => todo!(),
                Opcode::SET_FIELD => todo!(),
                Opcode::HALT => return Ok(()),
                Opcode::DESTRUCTURE_TUPLE => todo!(),
                Opcode::REGISTER_TRY => todo!(),
                Opcode::INSTANTIATE_CLASS => todo!(),
                Opcode::INSTANCE_OF => todo!(),
                Opcode::NOP => continue,
            }
        }
    }
    fn handle_bytecode_classes(&mut self, bytecode: &Bytecode) {
        todo!()
    }
    fn handle_bytecode_functions(&mut self, bytecode: &Bytecode) {
        todo!()
    }
}
