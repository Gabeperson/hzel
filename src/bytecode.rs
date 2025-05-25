extern crate alloc;

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Copy)]
enum Opcode {
    PUSH_NULL,
    PUSH_TRUE,
    PUSH_FALSE,
    PUSH_I64,
    PUSH_F64,
    PUSH_STR,
    POP,
    DUP,
    COPY,
    SWAP,
    MAKE_UPVALUE,
    ADD,
    SUB,
    MUL,
    DIV,
    MOD,
    NEG,
    EQ,
    NEQ,
    GT,
    LT,
    GTE,
    LTE,
    NOT,
    JMP,
    JMP_IF_TRUE,
    JMP_IF_FALSE,
    MAKE_ARRAY,
    MAKE_TUPLE,
    MAKE_MAP,
    // TODO make more
    INDEX,
    SET_INDEX,
    LEN,
    CALL,
    RET,
    ACCESS_FIELD,
    SET_FIELD,
    RUSTCALL,
    HALT,
    DESTRUCTURE_TUPLE,
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
        let mut result = 0u64;
        for (i, byte) in bytes.iter().copied().enumerate().take(10) {
            result |= ((byte & 0x7F) as u64) << (7 * i);
            if byte & 0x80 == 0 {
                return Some((result, i + 1));
            }
        }
        None
    }
}
