use hzel::lex;

fn main() {
    let f = std::fs::read_to_string("code.txt").unwrap();
    lex(&f);
}
