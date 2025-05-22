use chumsky::prelude::*;
use chumsky::text::ident;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TemplateStringFragment {
    String(String),
    Placeholder(Vec<Spanned<Token>>),
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token {
    If,
    While,
    For,
    Function,
    Null,
    Else,
    Let,
    Const,
    Return,
    Typeof,
    InstanceOf,
    Class,
    Try,
    Catch,
    New,
    // SelfKeyword,
    Identifier(String),
    HexLiteral(i64),
    DecLiteral(i64),
    FloatLiteral(f64),
    TemplateString(Vec<Spanned<TemplateStringFragment>>),
    String(String),
    Plus,
    Minus,
    Asterisk,
    Slash,
    Percent,
    PlusEquals,
    MinusEquals,
    AsteriskEquals,
    SlashEquals,
    PercentEquals,
    PlusPlus,
    MinusMinus,
    Eq,
    Eqeq,
    Neq,
    GT,
    GTE,
    LT,
    LTE,
    Ampersand,
    Pipe,
    Caret,
    Tilde,
    Shl,
    Shr,
    ShrUnsigned,
    AmpersandEquals,
    PipeEquals,
    CaretEquals,
    Exclamation,
    DoubleAmpersand,
    DoublePipe,
    ShlEquals,
    ShrEquals,
    ShrUnsignedEquals,
    LParen,
    RParen,
    LCurly,
    RCurly,
    LSquare,
    RSquare,
    Semicolon,
    Colon,
    Comma,
    Period,
    Spread,
}

impl PartialEq<Token> for &Token {
    fn eq(&self, other: &Token) -> bool {
        (*self).eq(other)
    }
}

pub(crate) type Span = SimpleSpan;

pub(crate) type Spanned<T> = (T, Span);

pub(crate) fn lexer<'src>()
-> impl Parser<'src, &'src str, Vec<Spanned<Token>>, extra::Err<Rich<'src, char, Span>>> {
    recursive(|lexer| {
        let ident_or_keyword = ident().map(|ident: &str| match ident {
            "if" => Token::If,
            "while" => Token::While,
            "for" => Token::For,
            "function" => Token::Function,
            "null" => Token::Null,
            "else" => Token::Else,
            "let" => Token::Let,
            "const" => Token::Const,
            "return" => Token::Return,
            "typeof" => Token::Typeof,
            "instanceof" => Token::InstanceOf,
            "class" => Token::Class,
            "try" => Token::Try,
            "catch" => Token::Catch,
            "new" => Token::New,
            // "self" => Token::SelfKeyword,
            _ => Token::Identifier(ident.to_owned()),
        });

        let float = text::int(10)
            .then(just("."))
            .then(text::int(10).or_not())
            .to_slice()
            .validate(|n: &str, ex, emitter| match n.parse::<f64>() {
                Ok(n) => n,
                Err(e) => {
                    emitter.emit(Rich::custom(ex.span(), e));
                    0.
                }
            })
            .map(Token::FloatLiteral);
        let hex = just("0x")
            .ignore_then(text::int(16))
            .to_slice()
            .validate(|n: &str, ex, emitter| match u64::from_str_radix(n, 16) {
                Ok(n) => n,
                Err(e) => {
                    emitter.emit(Rich::custom(ex.span(), e));
                    0
                }
            })
            .map(|n| Token::HexLiteral(n as i64));

        let dec = text::int(10)
            .to_slice()
            .validate(|n: &str, ex, emitter| match n.parse::<i64>() {
                Ok(n) => n,
                Err(e) => {
                    emitter.emit(Rich::custom(ex.span(), e));
                    0
                }
            })
            .map(Token::DecLiteral);

        let unicode_escape = |s, n| {
            just(s)
                .ignore_then(any().repeated().exactly(n).to_slice())
                .validate(|slice, ex, emitter| match u32::from_str_radix(slice, 16) {
                    Ok(n) => char::from_u32(n).unwrap(),
                    Err(e) => {
                        emitter.emit(Rich::custom(ex.span(), e));
                        '\u{26a0}'
                    }
                })
        };

        let string_escapes = || {
            choice((
                just(r#"\\"#).to('\\'),
                just(r#"\t"#).to('\t'),
                just(r#"\r"#).to('\r'),
                just(r#"\n"#).to('\n'),
                just(r#"\""#).to('\"'),
                just(r#"\'"#).to('\''),
                unicode_escape(r#"\x"#, 2),
                unicode_escape(r#"\u"#, 4),
                unicode_escape(r#"\U"#, 8),
            ))
            .labelled("string escape")
        };

        let string = string_escapes()
            .or(any().and_is(just("\"").not()))
            .repeated()
            .collect()
            .boxed()
            .map(Token::String)
            .delimited_by(just("\""), just("\""));

        // Probably some of the messiest code I've written. ever.
        let template_string = recursive(|template_string| {
            let simple_expr = recursive(|simple_expr| {
                choice((
                    simple_expr
                        .clone()
                        .delimited_by(just('{'), just('}'))
                        .ignored(),
                    simple_expr
                        .clone()
                        .delimited_by(just('('), just(')'))
                        .ignored(),
                    simple_expr
                        .clone()
                        .delimited_by(just('['), just(']'))
                        .ignored(),
                    string.clone().ignored(),
                    template_string.clone().ignored(),
                    any().and_is(just('}').not()).ignored(),
                ))
                .repeated()
                // .lazy()
                .to_slice()
                // TODO actually lex this
                // .map(|s: &str| s.to_owned())
            });

            lexer
                .nested_in(simple_expr)
                .map(TemplateStringFragment::Placeholder)
                .delimited_by(just("${"), just("}"))
                .or(string_escapes()
                    .or(just(r#"\`"#).to('`'))
                    .or(any().and_is(just('`').not()))
                    .repeated()
                    .at_least(1)
                    .collect::<String>()
                    .boxed()
                    .map(TemplateStringFragment::String))
                .map_with(|tsf, ex| (tsf, ex.span()))
                .repeated()
                .collect()
                .map(Token::TemplateString)
                .delimited_by(just("`"), just("`"))
        });
        let operator = choice((
            choice((
                just("<<=").to(Token::ShlEquals),
                just(">>=").to(Token::ShrEquals),
                just(">>>=").to(Token::ShrUnsignedEquals),
                just(">>>").to(Token::ShrUnsigned),
                just("==").to(Token::Eqeq),
                just("!=").to(Token::Neq),
                just(">=").to(Token::GTE),
                just("<=").to(Token::LTE),
                just(">>").to(Token::Shr),
                just("<<").to(Token::Shl),
                just("+=").to(Token::PlusEquals),
                just("-=").to(Token::MinusEquals),
                just("*=").to(Token::AsteriskEquals),
                just("/=").to(Token::SlashEquals),
                just("++").to(Token::PlusPlus),
                just("--").to(Token::MinusMinus),
                just("&=").to(Token::AmpersandEquals),
                just("%=").to(Token::PercentEquals),
                just("&&").to(Token::DoubleAmpersand),
                just("||").to(Token::DoublePipe),
            )),
            choice((
                just("...").to(Token::Spread),
                just("|=").to(Token::PipeEquals),
                just("^=").to(Token::CaretEquals),
                just("%").to(Token::Percent),
                just("=").to(Token::Eq),
                just("+").to(Token::Plus),
                just("-").to(Token::Minus),
                just("*").to(Token::Asterisk),
                just("/").to(Token::Slash),
                just(">").to(Token::GT),
                just("<").to(Token::LT),
                just("&").to(Token::Ampersand),
                just("|").to(Token::Pipe),
                just("^").to(Token::Caret),
                just("~").to(Token::Tilde),
                just("!").to(Token::Exclamation),
            )),
        ));

        let punct = choice((
            just("(").to(Token::LParen),
            just(")").to(Token::RParen),
            just("{").to(Token::LCurly),
            just("}").to(Token::RCurly),
            just("[").to(Token::LSquare),
            just("]").to(Token::RSquare),
            just(";").to(Token::Semicolon),
            just(":").to(Token::Colon),
            just(",").to(Token::Comma),
            just(".").to(Token::Period),
        ));
        let comment = just("//")
            .then(any().and_is(just('\n').not()).repeated())
            .padded();
        let token = choice((
            float,
            hex,
            dec,
            template_string,
            string,
            operator,
            punct,
            ident_or_keyword,
        ))
        .boxed();

        token
            .map_with(|t, ex| (t, ex.span()))
            .padded_by(comment.repeated())
            .padded()
            .repeated()
            .collect()
    })
}
