use chumsky::Parser;

// mod ast;
mod lexer;
// mod parser;

pub fn lex(s: &str) {
    dbg!(lexer::lexer().parse(s));
}
