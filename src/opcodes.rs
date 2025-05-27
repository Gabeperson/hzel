#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Copy, PartialEq)]
pub enum Opcode {
    /// LOAD_GLOBAL STRING
    /// Load the global variable at given string identifier onto stack
    LOAD_GLOBAL,
    /// STORE_GLOBAL STRING
    /// Store top of stack into global variable at given string identifier
    STORE_GLOBAL,
    /// DEFINE_GLOBAL STRING
    /// Define a new global with name STRING
    DEFINE_GLOBAL,
    /// Push null onto stack
    PUSH_NULL,
    /// Push true onto stack
    PUSH_TRUE,
    /// Push false onto stack
    PUSH_FALSE,
    /// PUSH_I64 i64
    /// Push an i64 onto stack
    PUSH_I64,
    /// PUSH_F64 f64
    /// Push an f64 onto stack
    PUSH_F64,
    /// PUSH_STR STRING
    /// Push string to top of stack
    PUSH_STR,
    /// STORE INDEX
    /// Store top of stack at INDEX
    STORE,
    /// LOAD INDEX
    /// Load INDEX to stack top
    LOAD,
    /// Remove top of stack
    POP,
    /// Duplicate top of stack
    DUP,
    /// swap top 2 values of stack
    SWAP,
    /// MAKE_UPVALUE INDEX
    /// Make INDEX an upvalue (if already one, noop)
    MAKE_UPVALUE,
    /// Add top two values on stack
    ADD,
    /// Subtract top value on stack from second value on stack
    SUB,
    /// Multiply top two values on stack
    MUL,
    /// Divide second value on stack by top value on stack
    DIV,
    /// Modulo second value on stack by top value on stack
    MOD,
    /// Negate top value on stack
    NEG,
    /// Apply the unary plus operator ex: +10, +100, ++10
    /// No-op technically, but here for custom structs once operator overloading implemented
    UNARY_PLUS,
    /// Check equality of top two values on stack
    EQ,
    /// Check inequality of top two values on stack
    NEQ,
    /// Push whether second value on stack is GT top value on stack
    GT,
    /// Push whether second value on stack is LT top value on stack
    LT,
    /// Push whether second value on stack is GTE top value on stack
    GTE,
    /// Push whether second value on stack is LTE top value on stack
    LTE,
    /// Apply logical NOT operator to top of stack
    NOT,
    /// Apply logical AND operator to top two values of stack
    AND,
    /// Apply logical OR operator to top two values of stack
    OR,
    /// Apply bitwise XOR operator to top two values of stack
    XOR,
    /// Apply bitwise NOT operator to top two values of stack
    BITNOT,
    /// Apply bitwise AND operator to top two values of stack
    BITAND,
    /// Apply bitwise OR operator to top two values of stack
    BITOR,
    /// Shift second value on stack LEFT by top value
    SHL,
    /// Shift second value on stack RIGHT by top value
    SHR,
    /// Shift second value on stack RIGHT by top value, without sign extension
    SHR_UNSIGNED,
    /// INC INDEX
    /// Increment the variable at INDEX
    INC,
    /// DEC INDEX
    /// Decrement the variable at INDEX
    DEC,
    /// JMP i64
    /// Jump relative amount of bytecode from location
    JMP,
    /// JMP_ABSOLUTE usize
    /// Jump to the absolute address in instruction
    JMP_ABSOLUTE,
    /// JMP_IF_TRUE i64
    /// Jump relative amount of bytecode from location IF true on stack
    JMP_IF_TRUE,
    /// JMP_IF_TRUE i64
    /// Jump relative amount of bytecode from location IF false on stack
    JMP_IF_FALSE,
    /// MAKE_ARRAY VARINT
    /// Pull n items from stack and make an array from it
    /// Deepest value in stack becomes the first value in array
    MAKE_ARRAY,
    /// MAKE_TUPLE VARINT
    /// Pull n items from stack and make a tuple from it
    /// Deepest value in stack becomes the first value in tuple
    MAKE_TUPLE,
    /// MAKE_MAP VARINT
    /// Pull n*2 items from stack and make a hashmap from it
    /// Values are interpreted as Key, Value, Key, Value, etc.
    MAKE_MAP,
    /// Index the second value of stack with top value
    INDEX,
    /// Assign the top value of stack to the third from top value indexed by the second value
    /// third[second] = top
    SET_INDEX,
    /// Get length of TOP of stack
    LEN,
    /// CALL N
    /// Call function at top of stack with N arguments below that
    /// Used for both native & VM calls
    CALL,

    /// Return from current stack frame with top of stack
    /// If returning from top level, return from execution.
    RET,
    /// ACCESS_FIELD STRING
    /// Load the STRING field of top of stack and push to stack.
    ACCESS_FIELD,
    /// SET_FIELD STRING
    /// Set the STRING field of second of stack with top of stack.
    SET_FIELD,
    /// Stop execution.
    HALT,
    /// DESTRUCTURE_TUPLE LEN
    /// Try to destructure the tuple's "internals" into the stack.
    ///
    /// Ex: given (a, b, c), PUSH a, PUSH b, PUSH c is performed.
    ///
    /// Fails if lengths given and length of tuple mismatch
    DESTRUCTURE_TUPLE,
    /// TODO
    REGISTER_TRY,
    /// TODO
    INSTANTIATE_CLASS,
    /// INSTANCE_OF STRING
    /// Push onto stack whether top of stack is a subclass of class with given string identifier
    INSTANCE_OF,
    /// Perform a no-op (Just skip this instruction)
    NOP,
}

impl Opcode {
    pub fn parse_u8(n: u8) -> Option<Self> {
        use Opcode::*;
        Some(match n {
            0 => LOAD_GLOBAL,
            1 => STORE_GLOBAL,
            2 => DEFINE_GLOBAL,
            3 => PUSH_NULL,
            4 => PUSH_TRUE,
            5 => PUSH_FALSE,
            6 => PUSH_I64,
            7 => PUSH_F64,
            8 => PUSH_STR,
            9 => STORE,
            10 => LOAD,
            11 => POP,
            12 => DUP,
            13 => SWAP,
            14 => MAKE_UPVALUE,
            15 => ADD,
            16 => SUB,
            17 => MUL,
            18 => DIV,
            19 => MOD,
            20 => NEG,
            21 => UNARY_PLUS,
            22 => EQ,
            23 => NEQ,
            24 => GT,
            25 => LT,
            26 => GTE,
            27 => LTE,
            28 => NOT,
            29 => AND,
            30 => OR,
            31 => XOR,
            32 => BITNOT,
            33 => BITAND,
            34 => BITOR,
            35 => SHL,
            36 => SHR,
            37 => SHR_UNSIGNED,
            38 => INC,
            39 => DEC,
            40 => JMP,
            41 => JMP_ABSOLUTE,
            42 => JMP_IF_TRUE,
            43 => JMP_IF_FALSE,
            44 => MAKE_ARRAY,
            45 => MAKE_TUPLE,
            46 => MAKE_MAP,
            47 => INDEX,
            48 => SET_INDEX,
            49 => LEN,
            50 => CALL,
            51 => RET,
            52 => ACCESS_FIELD,
            53 => SET_FIELD,
            54 => HALT,
            55 => DESTRUCTURE_TUPLE,
            56 => REGISTER_TRY,
            57 => INSTANTIATE_CLASS,
            58 => INSTANCE_OF,
            59 => NOP,
            _ => {
                return None;
            }
        })
    }
}

#[test]
fn opcode_decode_encode_sanity_check() {
    // Make sure enum and decode don't get out of sync
    for i in u8::MIN..=u8::MAX {
        if let Some(opcode) = Opcode::parse_u8(i) {
            assert_eq!(opcode as u8, i);
        }
    }
}

#[test]
fn opcode_encode_decode_sanity_check() {
    use Opcode::*;
    let arr = &[
        LOAD_GLOBAL,
        STORE_GLOBAL,
        DEFINE_GLOBAL,
        PUSH_NULL,
        PUSH_TRUE,
        PUSH_FALSE,
        PUSH_I64,
        PUSH_F64,
        PUSH_STR,
        STORE,
        LOAD,
        POP,
        DUP,
        SWAP,
        MAKE_UPVALUE,
        ADD,
        SUB,
        MUL,
        DIV,
        MOD,
        NEG,
        UNARY_PLUS,
        EQ,
        NEQ,
        GT,
        LT,
        GTE,
        LTE,
        NOT,
        AND,
        OR,
        XOR,
        BITNOT,
        BITAND,
        BITOR,
        SHL,
        SHR,
        SHR_UNSIGNED,
        INC,
        DEC,
        JMP,
        JMP_ABSOLUTE,
        JMP_IF_TRUE,
        JMP_IF_FALSE,
        MAKE_ARRAY,
        MAKE_TUPLE,
        MAKE_MAP,
        INDEX,
        SET_INDEX,
        LEN,
        CALL,
        RET,
        ACCESS_FIELD,
        SET_FIELD,
        HALT,
        DESTRUCTURE_TUPLE,
        REGISTER_TRY,
        INSTANTIATE_CLASS,
        INSTANCE_OF,
        NOP,
    ];
    for op in arr {
        let op = Opcode::parse_u8(*op as u8);
        op.unwrap();
    }
}

pub mod varint {
    extern crate alloc;
    use alloc::vec::Vec;

    pub fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            buf.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        buf.push(value as u8);
    }

    pub fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
        let mut result = 0;
        for (i, byte) in bytes.iter().copied().enumerate().take(10) {
            result |= ((byte & 0x7F) as u64) << (7 * i);
            if byte & 0x80 == 0 {
                return Some((result, i + 1));
            }
        }
        None
    }
}
