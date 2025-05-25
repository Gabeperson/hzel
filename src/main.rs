// use hzel::parse;

fn main() {
    let f = std::fs::read_to_string("code.txt").unwrap();
    // parse(&f);
    hzel::parse(&f);
}
