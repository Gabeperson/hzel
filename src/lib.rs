mod ast;
mod lexer;
mod parser;

// pub fn lex(s: &str) {
//     let mut lexer = Lexer::new(s);
//     let lexed = lexer.lex();
//     dbg!(&lexed);
//     dbg!(&lexer);
// }

pub fn parse(s: &str) {
    let now = std::time::Instant::now();
    let mut lexer = lexer::Lexer::new(s);
    let lexed = lexer.lex();
    let lextime = now.elapsed();
    let now = std::time::Instant::now();
    let mut parser = parser::Parser::new(&lexed);
    let parsed = parser.parse_file();
    let parsetime = now.elapsed();
    let errs = parser.into_errs();
    dbg!(lexer.errors);
    dbg!(parsed);
    dbg!(errs);
    dbg!(lextime);
    dbg!(parsetime);
}
