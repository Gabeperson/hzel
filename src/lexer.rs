use std::num::{ParseFloatError, ParseIntError};

#[derive(Clone, Copy, Debug)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Spanned<T>(pub T, pub Span);

impl<T: PartialEq> PartialEq for Spanned<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TemplateStringFragment {
    String(String),
    Placeholder(Vec<Spanned<Token>>),
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token {
    EOF,
    If,
    While,
    For,
    Function,
    Null,
    Else,
    Let,
    Return,
    Typeof,
    InstanceOf,
    Class,
    Try,
    Catch,
    New,
    SelfKeyword,
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
    RArrow,
    GTE,
    LArrow,
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
    Mut,
    Arrow,
    Err,
}

#[derive(Debug, Clone)]
pub(crate) enum LexingError {
    LoneHexPrefix(Span),
    InvalidCharactersInNumber(Span),
    IntLiteralParseError(ParseIntError, Span),
    FloatParseError(ParseFloatError, Span),
    InvalidHexSequence(Span),
    InvalidStringEscape(char, Span),
    EofInMiddleOfString(Span),
    UnrecognizedCharacters(Span),
}

#[derive(Debug, Clone)]
pub(crate) struct Lexer<'src> {
    pub(crate) input: &'src str,
    pub(crate) cursor: usize,
    pub(crate) errors: Vec<LexingError>,
    pub(crate) in_err: bool,
    pub(crate) err_start: usize,
}

impl<'src> Lexer<'src> {
    pub fn new(input: &'src str) -> Self {
        Self {
            input,
            cursor: 0,
            errors: Vec::new(),
            in_err: false,
            err_start: 0,
        }
    }
    fn is_empty(&self) -> bool {
        self.input.len() <= self.cursor
    }
    fn slice(&self) -> &'src str {
        &self.input[self.cursor..]
    }
    fn len(&self) -> usize {
        self.input.len() - self.cursor
    }
    fn bumpn(&mut self, n: usize) {
        self.cursor += n;
    }
    #[track_caller]
    fn current(&self) -> char {
        self.slice().chars().next().unwrap()
    }
}

impl Lexer<'_> {
    pub(crate) fn lex(&mut self) -> Vec<Spanned<Token>> {
        let mut tokens = Vec::new();
        let mut nested_comments = 0;
        while !self.is_empty() {
            if self.current().is_whitespace() {
                self.bumpn(1);
                continue;
            }
            if self.slice().starts_with("*/") {
                self.bumpn(2);
                nested_comments -= 1;
                continue;
            }
            if self.slice().starts_with("/*") {
                self.bumpn(2);
                nested_comments += 1;
                continue;
            }
            if nested_comments != 0 {
                self.bumpn(1);
                continue;
            }
            if self.slice().starts_with("//") {
                let line_end = self
                    .slice()
                    .find("\n")
                    .unwrap_or(self.input.len() - self.len())
                    + 1;
                self.cursor += line_end;
                continue;
            }
            let start = self.cursor;
            if let Some(t) = self.try_parse_operator() {
                tokens.push(t);
                self.done_error(start);
                continue;
            }
            if let Some(t) = self.try_parse_ident_or_keyword() {
                tokens.push(t);
                self.done_error(start);
                continue;
            }
            if let Some(t) = self.try_parse_number() {
                tokens.push(t);
                self.done_error(start);
                continue;
            }
            if let Some(t) = self.try_parse_string() {
                tokens.push(t);
                self.done_error(start);
                continue;
            }
            if let Some(t) = self.try_parse_template() {
                tokens.push(t);
                self.done_error(start);
                continue;
            }
            self.err_start = self.cursor;
            self.in_err = true;
            self.cursor += 1;
        }
        tokens
    }

    fn done_error(&mut self, when: usize) {
        if self.in_err {
            self.errors
                .push(LexingError::UnrecognizedCharacters(Span::new(
                    self.err_start,
                    when,
                )));
            self.in_err = false;
        }
    }

    fn try_parse_operator(&mut self) -> Option<Spanned<Token>> {
        let ops = &[
            ("<<=", Token::ShlEquals),
            (">>=", Token::ShrEquals),
            (">>>=", Token::ShrUnsignedEquals),
            (">>>", Token::ShrUnsigned),
            ("==", Token::Eqeq),
            ("!=", Token::Neq),
            (">=", Token::GTE),
            ("<=", Token::LTE),
            (">>", Token::Shr),
            ("<<", Token::Shl),
            ("+=", Token::PlusEquals),
            ("-=", Token::MinusEquals),
            ("*=", Token::AsteriskEquals),
            ("/=", Token::SlashEquals),
            ("++", Token::PlusPlus),
            ("--", Token::MinusMinus),
            ("&=", Token::AmpersandEquals),
            ("%=", Token::PercentEquals),
            ("&&", Token::DoubleAmpersand),
            ("||", Token::DoublePipe),
            ("->", Token::Arrow),
            ("|=", Token::PipeEquals),
            ("^=", Token::CaretEquals),
            ("%", Token::Percent),
            ("=", Token::Eq),
            ("+", Token::Plus),
            ("-", Token::Minus),
            ("*", Token::Asterisk),
            ("/", Token::Slash),
            (">", Token::RArrow),
            ("<", Token::LArrow),
            ("&", Token::Ampersand),
            ("|", Token::Pipe),
            ("^", Token::Caret),
            ("~", Token::Tilde),
            ("!", Token::Exclamation),
            ("(", Token::LParen),
            (")", Token::RParen),
            ("{", Token::LCurly),
            ("}", Token::RCurly),
            ("[", Token::LSquare),
            ("]", Token::RSquare),
            (";", Token::Semicolon),
            (":", Token::Colon),
            (",", Token::Comma),
            (".", Token::Period),
        ];
        let slice = self.slice();
        let start = self.cursor;
        for (prefix, token) in ops.iter() {
            if slice.starts_with(prefix) {
                self.bumpn(prefix.len());
                let end = self.cursor;
                return Some(Spanned(token.clone(), Span::new(start, end)));
            }
        }
        None
    }

    fn try_parse_ident_or_keyword(&mut self) -> Option<Spanned<Token>> {
        let start = self.cursor;
        let first = self.current();
        if !first.is_ascii_alphabetic() && first != '_' {
            return None;
        }
        let len = self
            .slice()
            .as_bytes()
            .iter()
            .position(|b| !matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
            .unwrap_or(self.len());
        let ident = &self.slice()[..len];
        self.bumpn(len);
        let end = self.cursor;
        let tok = match ident {
            "if" => Token::If,
            "while" => Token::While,
            "for" => Token::For,
            "fn" => Token::Function,
            "null" => Token::Null,
            "else" => Token::Else,
            "let" => Token::Let,
            "return" => Token::Return,
            "typeof" => Token::Typeof,
            "instanceof" => Token::InstanceOf,
            "class" => Token::Class,
            "try" => Token::Try,
            "catch" => Token::Catch,
            "new" => Token::New,
            "mut" => Token::Mut,
            "self" => Token::SelfKeyword,
            _ => Token::Identifier(ident.to_owned()),
        };
        Some(Spanned(tok, Span::new(start, end)))
    }

    fn try_parse_number(&mut self) -> Option<Spanned<Token>> {
        let first = self.current();
        if !first.is_ascii_digit() {
            return None;
        }
        if let Some(hex) = self.parse_hex() {
            return Some(hex);
        }
        self.parse_float_or_dec()
    }
    fn parse_hex(&mut self) -> Option<Spanned<Token>> {
        let start = self.cursor;
        if !self.slice().starts_with("0x") {
            return None;
        }
        self.bumpn(2);
        if !self.current().is_ascii_hexdigit() {
            self.errors.push(LexingError::LoneHexPrefix(Span::new(
                self.cursor,
                self.cursor + 1,
            )));
            return Some(Spanned(Token::Err, Span::new(0, 0)));
        }
        let len = self
            .slice()
            .as_bytes()
            .iter()
            .position(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..b'F'))
            .unwrap_or(self.len());
        let slice = &self.slice()[..len];
        self.bumpn(len);
        let end = self.cursor;
        let num = match u64::from_str_radix(slice, 16) {
            Ok(n) => n,
            Err(e) => {
                self.errors
                    .push(LexingError::IntLiteralParseError(e, Span::new(start, end)));
                return Some(Spanned(Token::Err, Span::new(0, 0)));
            }
        };
        Some(Spanned(
            Token::HexLiteral(num as i64),
            Span::new(start, end),
        ))
    }
    fn parse_float_or_dec(&mut self) -> Option<Spanned<Token>> {
        let start = self.cursor;
        let len = self
            .slice()
            .as_bytes()
            .iter()
            .position(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            .unwrap_or(self.len());
        self.bumpn(len);
        let int_end = self.cursor;
        // Possibilities: 10 or 10. or 10.0 or 10.method()
        if self.is_empty() || self.current() != '.' {
            let num = match self.input[start..start + len].parse::<i64>() {
                Ok(n) => n,
                Err(e) => {
                    self.errors.push(LexingError::IntLiteralParseError(
                        e,
                        Span::new(start, int_end),
                    ));
                    return Some(Spanned(Token::Err, Span::new(0, 0)));
                }
            };
            return Some(Spanned(Token::DecLiteral(num), Span::new(start, int_end)));
        }
        // Possibilities: 10. or 10.0 or 10.method()
        self.bumpn(1);
        let next = self.current();
        if next.is_ascii_alphabetic() {
            // 10.method()
            let num = match self.input[start..start + len].parse::<i64>() {
                Ok(n) => n,
                Err(e) => {
                    self.errors.push(LexingError::IntLiteralParseError(
                        e,
                        Span::new(start, int_end),
                    ));
                    return Some(Spanned(Token::Err, Span::new(0, 0)));
                }
            };
            Some(Spanned(Token::DecLiteral(num), Span::new(start, int_end)))
        } else if next.is_ascii_digit() {
            // 10.0
            let len2 = self
                .slice()
                .as_bytes()
                .iter()
                .position(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                .unwrap_or(self.len());
            self.bumpn(len);
            let num = match self.input[start..start + len + 1 + len2].parse::<f64>() {
                Ok(n) => n,
                Err(e) => {
                    self.errors
                        .push(LexingError::FloatParseError(e, Span::new(start, int_end)));
                    return Some(Spanned(Token::Err, Span::new(0, 0)));
                }
            };
            return Some(Spanned(Token::FloatLiteral(num), Span::new(start, int_end)));
        } else {
            // 10.
            let num = match self.input[start..start + len + 1].parse::<f64>() {
                Ok(n) => n,
                Err(e) => {
                    self.errors
                        .push(LexingError::FloatParseError(e, Span::new(start, int_end)));
                    return Some(Spanned(Token::Err, Span::new(0, 0)));
                }
            };
            return Some(Spanned(Token::FloatLiteral(num), Span::new(start, int_end)));
        }
    }
    // TODO UNPUBLIC
    pub fn try_parse_string(&mut self) -> Option<Spanned<Token>> {
        let start = self.cursor;
        if self.current() != '\"' {
            return None;
        }
        self.bumpn(1);
        let mut string = String::new();
        loop {
            if let Some(c) = self.try_parse_escape() {
                string.push(c);
            } else {
                if self.is_empty() {
                    self.errors.push(LexingError::EofInMiddleOfString(Span::new(
                        self.cursor,
                        self.cursor + 1,
                    )));
                    return Some(Spanned(Token::Err, Span::new(0, 0)));
                }
                let curr = self.current();
                self.bumpn(1);
                if curr == '"' {
                    return Some(Spanned(
                        Token::String(string),
                        Span::new(start, self.cursor),
                    ));
                }
                string.push(curr);
            }
        }
    }
    // TODO unpublic
    pub fn try_parse_template(&mut self) -> Option<Spanned<Token>> {
        let start = self.cursor;
        if self.current() != '`' {
            return None;
        }
        self.bumpn(1);
        let mut vec = Vec::new();
        let mut string = String::new();
        loop {
            let start2 = self.cursor;
            if self.current() == '`' {
                self.bumpn(1);
                return Some(Spanned(
                    Token::TemplateString(vec),
                    Span::new(start, self.cursor),
                ));
            }
            if self.slice().starts_with("${") {
                self.bumpn(2);
                let start_expr = self.cursor;
                let mut curly_count = 0;
                loop {
                    if self.try_parse_string().is_some() {
                        continue;
                    }
                    if self.try_parse_template().is_some() {
                        continue;
                    }
                    if self.current() == '{' {
                        curly_count += 1;
                        self.bumpn(1);
                        continue;
                    }
                    if self.current() == '}' {
                        if curly_count == 0 {
                            break;
                        }
                        curly_count -= 1;
                    }
                    self.bumpn(1);
                }
                let end_expr = self.cursor;
                self.bumpn(1);
                let mut lexer = Lexer {
                    input: &self.input[..end_expr],
                    cursor: start_expr,
                    in_err: false,
                    err_start: 0,
                    // Doing this saves potentially an allocation
                    errors: std::mem::take(&mut self.errors),
                };
                let tokens = lexer.lex();
                // Put it back
                std::mem::swap(&mut lexer.errors, &mut self.errors);
                vec.push(Spanned(
                    TemplateStringFragment::Placeholder(tokens),
                    Span::new(start_expr, end_expr),
                ));
                continue;
            }
            loop {
                if let Some(c) = self.try_parse_escape() {
                    string.push(c);
                } else {
                    if self.is_empty() {
                        self.errors.push(LexingError::EofInMiddleOfString(Span::new(
                            self.cursor,
                            self.cursor + 1,
                        )));
                        return None;
                    }
                    if self.current() == '`' || self.slice().starts_with("${") {
                        let end2 = self.cursor;
                        vec.push(Spanned(
                            TemplateStringFragment::String(string),
                            Span::new(start2, end2),
                        ));
                        string = String::new();
                        break;
                    }
                    string.push(self.current());
                    self.bumpn(1);
                }
            }
        }
    }
    fn try_parse_escape(&mut self) -> Option<char> {
        if self.current() != '\\' {
            return None;
        }
        self.bumpn(1);
        let curr = self.current();
        self.bumpn(1);
        match curr {
            '\\' => Some('\\'),
            't' => Some('\t'),
            'r' => Some('\r'),
            'n' => Some('\n'),
            '"' => Some('"'),
            '`' => Some('`'),
            '\'' => Some('\''),
            'x' => Some(self.hex_escape(2)),
            'u' => Some(self.hex_escape(4)),
            'U' => Some(self.hex_escape(8)),
            other => {
                self.errors.push(LexingError::InvalidStringEscape(
                    other,
                    Span::new(self.cursor, self.cursor + 1),
                ));
                Some('_')
            }
        }
    }
    fn hex_escape(&mut self, n: usize) -> char {
        let start = self.cursor;
        if self.slice().len() < n {
            self.errors.push(LexingError::InvalidHexSequence(Span::new(
                start,
                self.input.len(),
            )));
            return '_';
        }
        if self.slice()[..n].chars().all(|c| c.is_ascii_hexdigit()) {
            let c = char::from_u32(u32::from_str_radix(&self.slice()[..n], 16).unwrap());
            self.bumpn(n);
            if let Some(c) = c {
                return c;
            }
            self.errors.push(LexingError::InvalidHexSequence(Span::new(
                start,
                self.cursor,
            )));
            return '_';
        }
        self.errors.push(LexingError::InvalidHexSequence(Span::new(
            start,
            self.cursor,
        )));
        '_'
    }
}

impl PartialEq<Token> for &Token {
    fn eq(&self, other: &Token) -> bool {
        (*self).eq(&other)
    }
}
