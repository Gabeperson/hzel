use chumsky::Parser;

mod ast;
mod lexer;
pub(crate) mod parser;

pub fn parse(s: &str) {
    let now = std::time::Instant::now();
    let lexed = lexer::lexer().parse(s).unwrap();
    let lextime = now.elapsed();
    let now = std::time::Instant::now();
    let mut parser = parser::Parser::new(&lexed);
    let parsed = parser.parse_file();
    let parsetime = now.elapsed();
    let errs = parser.into_errs();
    dbg!(parsed);
    dbg!(errs);
    dbg!(lextime);
    dbg!(parsetime);
}
