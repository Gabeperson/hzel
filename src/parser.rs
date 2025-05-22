use std::borrow::Cow;
use std::panic::Location;

use super::ast::*;
use super::lexer;
use super::lexer::*;

#[derive(Debug, Clone)]
pub(crate) struct ParsingError {
    pub(crate) span: Span,
    pub(crate) typ: ParsingErrorType,
}

impl ParsingError {
    fn new(span: Span, typ: PET) -> Self {
        Self { span, typ }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
pub(crate) enum ParsingErrorType {
    // TODO: Wrong delimiter (, {, [
    EOF,
    WrongToken {
        expected: ExpectedToken,
        found: Token,
    },
    ExpectedSemicolon {
        found: Token,
    },
    EmptyCondition,
    EmptyCatchBracket,
    InvalidStmtTypeForBody(StmtBodyType),
    EmptyFor,
    UnmatchedCloseBracket(Token),
    TokenAfterSpread,
    InvalidTemplateStringPlaceholder,
    TemplateStringPlaceholderRemainingTokens,
    MismatchedDelimiter {
        expected: Token,
        found: Token,
    },
}

#[derive(Debug, Clone)]
enum StmtBodyType {
    If,
    While,
    For,
    Else,
}

impl ParsingErrorType {
    // fn eof(expected: impl Into<Cow<'static, str>>) -> Self {
    //     Self::EOF {
    //         expected: expected.into(),
    //     }
    // }
    fn wrong_token(expected: ExpectedToken, found: Token) -> Self {
        Self::WrongToken { expected, found }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ExpectedToken {
    Token(Token),
    OneOfTwo(Token, Token),
    OneOfThree(Token, Token, Token),
    TokenType(Cow<'static, str>),
}

pub(crate) enum VarDeclType {
    Let,
    Const,
}

use ExpectedToken as ET;
use ParsingErrorType as PET;

#[derive(Debug, Clone)]
pub(crate) struct Parser<'src> {
    tokens: &'src [(Token, Span)],
    cursor: usize,
    errors: Vec<ParsingError>,
}

impl<'src> Parser<'src> {
    pub(crate) fn new(tokens: &'src [(Token, Span)]) -> Self {
        Parser {
            tokens,
            cursor: 0,
            errors: Vec::new(),
        }
    }
    pub(crate) fn into_errs(self) -> Vec<ParsingError> {
        self.errors
    }
    fn current(&self) -> &Token {
        &(self.tokens[self.cursor].0)
    }
    fn next(&self) -> Option<&Token> {
        self.tokens.get(self.cursor + 1).map(|ts| &ts.0)
    }
    fn span(&self) -> Span {
        self.tokens[self.cursor].1
    }
    fn span_start(&self) -> usize {
        self.span().start
    }
    fn prev_span_end(&self) -> usize {
        self.tokens[self.cursor - 1].1.end
    }
    fn prev_span(&self) -> Span {
        self.tokens[self.cursor - 1].1
    }
    fn span_end(&self) -> usize {
        self.span().end
    }
    fn new_span(&self, start: usize, end: usize) -> Span {
        Span::from(start..end)
    }
    fn bump(&mut self) {
        self.cursor += 1;
    }
    fn bumpe(&mut self) -> Option<()> {
        self.cursor += 1;
        if self.is_empty() {
            self.error(ParsingError::new(
                self.new_span(self.prev_span_end(), self.prev_span_end() + 1),
                ParsingErrorType::EOF,
            ));
            return None;
        }
        Some(())
    }
    fn bumpn(&mut self, n: usize) {
        self.cursor += n;
    }
    fn is_empty(&self) -> bool {
        self.tokens.len() <= self.cursor
    }
    fn error(&mut self, error: ParsingError) {
        self.errors.push(error)
    }

    fn skip_maybe_semicolon(&mut self) -> Option<()> {
        if self.current() == Token::Semicolon {
            self.bumpe()?;
            return Some(());
        }
        self.error(ParsingError::new(
            self.span(),
            ParsingErrorType::WrongToken {
                expected: ExpectedToken::Token(Token::Semicolon),
                found: self.current().clone(),
            },
        ));
        Some(())
    }

    fn recover_stmt(&mut self) {
        while !self.is_empty() && self.current() != Token::Semicolon {
            self.bump();
        }
        self.bump();
    }
    fn recover_until(&mut self, t: Token) {
        while !self.is_empty() && self.current() != t {
            self.bump();
        }
    }
    fn recover_until_stmt_start(&mut self) {
        while !self.is_empty() && !self.is_stmt_start() {
            self.bump();
        }
        if !self.is_empty() && self.current() == Token::RCurly || self.current() == Token::Semicolon
        {
            self.bump();
        }
    }
    fn is_stmt_start(&self) -> bool {
        matches!(
            self.current(),
            Token::Let
                | Token::Const
                | Token::If
                | Token::While
                | Token::For
                | Token::Return
                | Token::LCurly
                | Token::RCurly
                | Token::Semicolon
                | Token::Function
                | Token::Try
                | Token::Catch
                | Token::Class
        )
    }
}

impl<'src> Parser<'src> {
    pub(crate) fn parse_file(&mut self) -> File {
        let mut stmts = Vec::new();
        while !self.is_empty() {
            if let Some(stmt) = self.parse_stmt() {
                stmts.push(stmt)
            }
        }
        File { stmts }
    }

    fn parse_stmt(&mut self) -> Option<Spanned<Stmt>> {
        let stmt = match self.current() {
            Token::Let => self.parse_vardecl(VarDeclType::Let),
            Token::Const => self.parse_vardecl(VarDeclType::Const),
            Token::If => return self.parse_if(),
            Token::While => return self.parse_while(),
            Token::For => return self.parse_for(),
            Token::Return => self.parse_return(),
            Token::LCurly => {
                return self
                    .parse_block()
                    .map(|(block, span)| (Stmt::Block((block, span)), span));
            }
            Token::Function => return self.parse_function(),
            Token::Try => return self.parse_trycatch(),
            Token::Class => todo!(),
            Token::RCurly | Token::RParen | Token::RSquare => {
                self.error(ParsingError::new(
                    self.span(),
                    PET::UnmatchedCloseBracket(self.current().clone()),
                ));
                self.bump();
                return None;
            }
            Token::Semicolon => {
                let span = self.span();
                Some((Stmt::Empty, span))
            }
            _ => {
                let expr = self
                    .parse_expr()
                    .map(|(expr, span)| (Stmt::ExprStmt((expr, span)), span));
                if expr.is_none() {
                    self.recover_stmt();
                    return None;
                }
                expr
            }
        };
        if self.current() == Token::Semicolon {
            self.bump();
        } else {
            self.error(ParsingError::new(
                self.span(),
                ParsingErrorType::ExpectedSemicolon {
                    found: self.current().clone(),
                },
            ));
        }
        stmt
    }

    fn parse_trycatch(&mut self) -> Option<Spanned<Stmt>> {
        let start = self.span_start();
        if self.current() != Token::Try {
            panic!("Internal compiler error. Expected try, found something else");
        } else {
            self.bumpe()?;
        };
        let tryblock = self.parse_block()?;
        if self.current() != Token::Catch {
            self.error(ParsingError::new(
                self.span(),
                PET::wrong_token(ExpectedToken::Token(Token::Catch), self.current().clone()),
            ))
        } else {
            self.bumpe()?;
        }
        let mut errvar = None;
        'parseblck: {
            if self.current() == Token::LParen {
                self.bumpe()?;
                if self.current() == Token::RParen {
                    self.error(ParsingError::new(
                        self.span(),
                        ParsingErrorType::EmptyCatchBracket,
                    ));
                    self.bumpe()?;
                    break 'parseblck;
                }
                let pat = match self.parse_pat() {
                    Some(pat) => pat,
                    None => {
                        self.recover_stmt();
                        return None;
                    }
                };
                if self.current() != Token::RParen {
                    self.error(ParsingError::new(
                        self.span(),
                        PET::wrong_token(ET::Token(Token::RParen), self.current().clone()),
                    ));
                    self.recover_until_stmt_start();
                    return None;
                }
                self.bumpe()?;
                errvar = Some(pat);
            }
        }

        let catchblock = self.parse_block()?;
        let end = self.prev_span_end();
        Some((
            Stmt::TryCatch {
                try_block: tryblock,
                catch_param: errvar,
                catch_block: Box::new(catchblock),
            },
            self.new_span(start, end),
        ))
    }

    fn parse_function(&mut self) -> Option<Spanned<Stmt>> {
        let start = self.span_start();
        if self.current() != Token::Function {
            panic!("Internal compiler error. Expected function, found something else");
        } else {
            self.bumpe()?;
        };
        let ident = match self.current() {
            Token::Identifier(ident) => (Ident(ident.clone()), self.span()),
            other => {
                self.error(ParsingError::new(
                    self.span(),
                    PET::wrong_token(ET::Token(Token::Identifier(String::new())), other.clone()),
                ));
                return None;
            }
        };
        self.bumpe()?;
        let params = match self.parse_params() {
            Some(params) => params,
            None => {
                self.recover_until_stmt_start();
                return None;
            }
        };
        let body = self.parse_block()?;
        let end = self.prev_span_end();
        Some((
            Stmt::Function {
                name: ident,
                params,
                body,
            },
            self.new_span(start, end),
        ))
    }
    fn parse_params(&mut self) -> Option<Spanned<Vec<Spanned<Pattern>>>> {
        if self.current() != Token::LParen {
            panic!("Internal compiler error. Expected (, found something else");
        } else {
            self.bumpe()?;
        };
        // Check self, then parse
        let mut params = Vec::new();
        while !self.is_empty() && self.current() != Token::RParen {
            if let Some(param) = self.parse_pat() {
                params.push(param);
            }
            if self.current() == Token::Comma {
                self.bumpe()?;
            } else if !matches!(self.current(), Token::RParen) {
                // if there is no comma and we're not at RParen, then missing comma.
                // else it might be a trailing comma (a, b, c,)
                self.error(ParsingError::new(
                    self.span(),
                    PET::wrong_token(
                        ET::TokenType(Cow::Borrowed("parameter")),
                        self.current().clone(),
                    ),
                ))
            }
        }
        if self.is_empty() {
            self.error(ParsingError::new(self.prev_span(), PET::EOF));
            return None;
        }
        if self.current() != Token::RParen {
            self.error(ParsingError::new(
                self.span(),
                PET::wrong_token(ET::Token(Token::RParen), self.current().clone()),
            ));
            return None;
        }
        self.bumpe()?;
        let end = self.prev_span_end();
        Some((params, self.new_span(self.span_start(), end)))
    }

    fn parse_return(&mut self) -> Option<Spanned<Stmt>> {
        let start = self.span_start();
        if self.current() != Token::Return {
            panic!("Internal compiler error. Expected return, found something else");
        } else {
            self.bumpe()?;
        };
        if self.current() == Token::Semicolon {
            let span = self.prev_span();
            return Some((Stmt::Return(None), span));
        }
        let expr = self.parse_expr();
        let expr = if let Some(expr) = expr {
            expr
        } else {
            self.recover_stmt();
            return None;
        };
        let end = self.prev_span_end();
        let span = self.new_span(start, end);
        Some((Stmt::Return(Some(expr)), span))
    }

    fn parse_for(&mut self) -> Option<Spanned<Stmt>> {
        let start = self.span_start();
        if self.current() != Token::For {
            panic!("Internal compiler error. Expected for, found something else");
        } else {
            self.bumpe()?;
        };
        if self.current() != Token::LParen {
            self.error(ParsingError::new(
                self.span(),
                PET::wrong_token(ET::Token(Token::LParen), self.current().clone()),
            ));
            self.recover_until_stmt_start();
            return None;
        }
        self.bumpe()?;
        let first_stmt = match self.current() {
            Token::Semicolon => None,
            Token::RParen => {
                self.error(ParsingError::new(self.span(), ParsingErrorType::EmptyFor));
                self.recover_until_stmt_start();
                return None;
            }
            Token::Let => {
                let vardecl = self.parse_vardecl(VarDeclType::Let);
                if vardecl.is_none() {
                    self.recover_until_stmt_start();
                    return None;
                }

                self.skip_maybe_semicolon()?;
                vardecl
            }
            Token::Const => {
                let vardecl = self.parse_vardecl(VarDeclType::Const);
                if vardecl.is_none() {
                    self.recover_until_stmt_start();
                    return None;
                }
                vardecl
            }
            _ => {
                let expr = self.parse_expr();
                if expr.is_none() {
                    self.recover_until_stmt_start();
                    return None;
                }
                expr.map(|(expr, span)| (Stmt::ExprStmt((expr, span)), span))
            }
        };
        self.skip_maybe_semicolon()?;

        let condition = match self.current() {
            Token::Semicolon => None,
            _ => {
                let expr = self.parse_expr();
                if expr.is_none() {
                    self.recover_until_stmt_start();
                    return None;
                }
                expr
            }
        };
        self.skip_maybe_semicolon()?;
        let update = match self.current() {
            Token::RParen => None,
            _ => {
                let expr = self.parse_expr();
                if expr.is_none() {
                    self.recover_until_stmt_start();
                    return None;
                }
                expr
            }
        };
        if self.current() != Token::RParen {
            self.error(ParsingError::new(
                self.span(),
                ParsingErrorType::wrong_token(
                    ExpectedToken::Token(Token::RParen),
                    self.current().clone(),
                ),
            ));
            self.recover_until_stmt_start();
            return None;
        }
        self.bumpe()?;
        let body = self.parse_stmt()?;
        if self.is_invalid_stmt_body_type(&body.0) {
            self.error(ParsingError::new(
                body.1,
                PET::InvalidStmtTypeForBody(StmtBodyType::For),
            ));
            self.recover_until_stmt_start();
            return None;
        }
        let end = self.prev_span_end();
        Some((
            Stmt::For {
                init: first_stmt.map(Box::new),
                condition,
                update,
                body: Box::new(body),
            },
            self.new_span(start, end),
        ))
    }

    fn is_invalid_stmt_body_type(&self, stmt: &Stmt) -> bool {
        matches!(
            stmt,
            Stmt::ClassDecl { .. }
                | Stmt::Function { .. }
                | Stmt::LetDecl { .. }
                | Stmt::ConstDecl { .. }
        )
    }
    fn parse_if(&mut self) -> Option<Spanned<Stmt>> {
        let start = self.span_start();
        if self.current() != Token::If {
            panic!("Internal compiler error. Expected if, found something else");
        } else {
            self.bumpe()?;
        };
        let condition = self.parse_condition_bracketed();
        let condition = if let Some(condition) = condition {
            condition
        } else {
            self.recover_stmt();
            return None;
        };
        let body = self.parse_stmt()?;
        if self.is_invalid_stmt_body_type(&body.0) {
            self.error(ParsingError::new(
                body.1,
                PET::InvalidStmtTypeForBody(StmtBodyType::If),
            ));
            self.recover_until_stmt_start();
            return None;
        }
        let mut end = self.prev_span_end();
        let mut else_branch = None;
        if self.current() == Token::Else {
            self.bumpe()?;
            let stmt = self.parse_stmt()?;
            if self.is_invalid_stmt_body_type(&stmt.0) {
                self.error(ParsingError::new(
                    stmt.1,
                    PET::InvalidStmtTypeForBody(StmtBodyType::Else),
                ));
                self.recover_until_stmt_start();
                return None;
            }
            else_branch = Some(Box::new(stmt));
            end = self.prev_span_end();
        }
        Some((
            Stmt::If {
                condition,
                then_branch: Box::new(body),
                else_branch,
            },
            self.new_span(start, end),
        ))
    }

    fn parse_while(&mut self) -> Option<Spanned<Stmt>> {
        let start = self.span_start();
        if self.current() != Token::While {
            panic!("Internal compiler error. Expected while, found something else");
        } else {
            self.bumpe()?;
        };
        let condition = self.parse_condition_bracketed();
        let condition = if let Some(condition) = condition {
            condition
        } else {
            self.recover_stmt();
            return None;
        };
        let body = self.parse_stmt()?;
        if self.is_invalid_stmt_body_type(&body.0) {
            self.error(ParsingError::new(
                body.1,
                PET::InvalidStmtTypeForBody(StmtBodyType::While),
            ));
            self.recover_until_stmt_start();
            return None;
        }
        let end = self.prev_span_end();
        Some((
            Stmt::While {
                condition,
                body: Box::new(body),
            },
            self.new_span(start, end),
        ))
    }

    fn parse_condition_bracketed(&mut self) -> Option<Spanned<Expr>> {
        if self.current() != Token::LParen {
            self.error(ParsingError::new(
                self.span(),
                PET::wrong_token(ET::Token(Token::LParen), self.current().clone()),
            ));
            self.recover_until_stmt_start();
            return None;
        }
        if self.current() == Token::RParen {
            self.error(ParsingError::new(
                self.span(),
                ParsingErrorType::EmptyCondition,
            ));
            let span = self.span();
            self.bumpe()?;
            return Some((Expr::Err, span));
        }
        self.bumpe()?;
        let expr = self.parse_expr()?;
        if self.current() != Token::RParen {
            self.error(ParsingError::new(
                self.span(),
                PET::wrong_token(ET::Token(Token::RParen), self.current().clone()),
            ));
            self.recover_until_stmt_start();
            return None;
        }
        self.bumpe()?;
        Some(expr)
    }

    fn parse_block(&mut self) -> Option<Spanned<Block>> {
        let start = self.span_start();
        if self.current() != Token::LCurly {
            self.error(ParsingError::new(
                self.span(),
                PET::wrong_token(ET::Token(Token::LCurly), self.current().clone()),
            ));
            return None;
        }
        self.bumpe()?;

        let mut stmts = Vec::new();
        while !self.is_empty() && self.current() != Token::RCurly {
            if let Some(stmt) = self.parse_stmt() {
                stmts.push(stmt);
            }
        }
        if self.is_empty() {
            self.error(ParsingError::new(self.prev_span(), PET::EOF));
            return None;
        }
        if self.current() != Token::RCurly {
            self.error(ParsingError::new(
                self.span(),
                PET::wrong_token(ET::Token(Token::RCurly), self.current().clone()),
            ));
            return None;
        }

        let end = self.span_end();
        self.bump();

        Some((Block { inner: stmts }, self.new_span(start, end)))
    }

    fn parse_vardecl(&mut self, typ: VarDeclType) -> Option<Spanned<Stmt>> {
        let start = self.span_start();
        if self.current() != Token::Let && self.current() != Token::Const {
            panic!("Internal compiler error. Expected let/const, found something else");
        } else {
            self.bumpe()?;
        }

        let left = match self.parse_pat() {
            Some(pat) => pat,
            None => {
                self.recover_stmt();
                return None;
            }
        };
        match self.current() {
            Token::Semicolon => {
                let end = self.prev_span_end();
                return Some((
                    match typ {
                        VarDeclType::Let => Stmt::LetDecl {
                            lhs: left,
                            rhs: None,
                        },
                        VarDeclType::Const => Stmt::ConstDecl {
                            lhs: left,
                            rhs: None,
                        },
                    },
                    self.new_span(start, end),
                ));
            }
            Token::Eq => self.bumpe()?,
            other => {
                self.error(ParsingError::new(
                    self.span(),
                    PET::wrong_token(ET::OneOfTwo(Token::Eq, Token::Semicolon), other.clone()),
                ));
                self.bumpe()?;
                // recover `let x y = 5;`
                if self.current() != Token::Eq {
                    // Failed. recover line and continue
                    self.recover_stmt();
                    return None;
                }
            }
        }
        let right = self.parse_expr();
        let right = if let Some(expr) = right {
            expr
        } else {
            self.recover_stmt();
            return None;
        };
        let end = self.prev_span_end();
        self.bumpe()?;
        Some((
            match typ {
                VarDeclType::Let => Stmt::LetDecl {
                    lhs: left,
                    rhs: Some(right),
                },
                VarDeclType::Const => Stmt::ConstDecl {
                    lhs: left,
                    rhs: Some(right),
                },
            },
            self.new_span(start, end),
        ))
    }

    fn parse_pat(&mut self) -> Option<Spanned<Pattern>> {
        match self.current() {
            Token::LCurly => self.parse_pat_object(),
            Token::LSquare => self.parse_pat_array(),
            Token::Identifier(_) => self.parse_pat_ident(),
            _ => {
                self.error(ParsingError::new(
                    self.span(),
                    PET::wrong_token(
                        ExpectedToken::TokenType(Cow::Borrowed("pattern")),
                        self.current().clone(),
                    ),
                ));
                None
            }
        }
    }

    fn parse_pat_object(&mut self) -> Option<Spanned<Pattern>> {
        let start = self.span_start();
        if self.current() != Token::LCurly {
            panic!(
                "Internal compiler error. Expected object start {{ in pattern but found something else"
            );
        } else {
            self.bumpe()?
        };
        let mut list = Vec::new();
        loop {
            match self.current() {
                Token::RCurly => {
                    self.bumpe()?;
                    return Some((
                        Pattern::Object(list),
                        self.new_span(start, self.prev_span_end()),
                    ));
                }
                Token::String(string) => {
                    let expr = (
                        Expr::Literal((Literal::String(string.clone()), self.span())),
                        self.span(),
                    );
                    self.bumpe()?;
                    if self.current() != Token::Colon {
                        self.error(ParsingError::new(
                            self.span(),
                            PET::wrong_token(ET::Token(Token::Colon), self.current().clone()),
                        ));
                        return None;
                    }
                    self.bumpe()?;
                    let pat = self.parse_pat()?;
                    list.push((expr, Some(pat)));
                    match self.current() {
                        Token::RCurly | Token::Spread => {}
                        Token::Comma => {
                            self.bumpe()?;
                        }
                        other => {
                            self.error(ParsingError::new(
                                self.span(),
                                PET::wrong_token(
                                    ET::OneOfThree(Token::Comma, Token::Spread, Token::RCurly),
                                    other.clone(),
                                ),
                            ));
                            return None;
                        }
                    }
                }
                Token::Identifier(ident) => {
                    let expr = (
                        Expr::Identifier((Ident(ident.clone()), self.span())),
                        self.span(),
                    );
                    self.bumpe()?;
                    match self.current() {
                        Token::Comma => {
                            list.push((expr, None));
                            self.bumpe()?;
                            continue;
                        }
                        Token::RCurly => {
                            list.push((expr, None));
                            continue;
                        }
                        Token::Colon => {}
                        _ => {
                            self.error(ParsingError::new(
                                self.span(),
                                PET::wrong_token(
                                    ET::OneOfThree(Token::Colon, Token::Comma, Token::RCurly),
                                    self.current().clone(),
                                ),
                            ));
                            return None;
                        }
                    }
                    self.bumpe()?;
                    let pat = self.parse_pat()?;
                    list.push((expr, Some(pat)));
                    match self.current() {
                        Token::RCurly => {}
                        Token::Comma => {
                            self.bumpe()?;
                        }
                        other => {
                            self.error(ParsingError::new(
                                self.span(),
                                PET::wrong_token(
                                    ET::OneOfTwo(Token::Comma, Token::RCurly),
                                    other.clone(),
                                ),
                            ));
                            return None;
                        }
                    }
                }
                other => {
                    self.error(ParsingError::new(
                        self.span(),
                        PET::wrong_token(
                            ExpectedToken::TokenType(Cow::Borrowed("object pattern inner")),
                            other.clone(),
                        ),
                    ));
                    return None;
                }
            }
        }
    }

    fn parse_pat_ident(&mut self) -> Option<Spanned<Pattern>> {
        let ident = if let Token::Identifier(ident) = self.current() {
            Ident(ident.clone())
        } else {
            panic!("Internal Compiler Error. Expected ident in pattern but found something else");
        };
        let span = self.span();
        self.bumpe()?;
        Some((Pattern::Ident((ident, span)), span))
    }

    fn parse_pat_array(&mut self) -> Option<Spanned<Pattern>> {
        let start = self.span_start();
        if self.current() != Token::LSquare {
            panic!("Internal Compiler Error. Expected [ in pattern but found something else");
        } else {
            self.bumpe()?;
        };
        let mut list = Vec::new();

        loop {
            match self.current() {
                Token::RSquare => {
                    self.bumpe()?;
                    return Some((
                        Pattern::Array(list, None),
                        self.new_span(start, self.prev_span_end()),
                    ));
                }
                Token::Comma => {
                    list.push(None);
                    self.bumpe()?;
                }
                Token::Spread => {
                    self.bumpe()?;
                    let pat = self.parse_pat()?;
                    if self.current() != Token::LSquare {
                        self.error(ParsingError {
                            span: self.span(),
                            typ: ParsingErrorType::TokenAfterSpread,
                        })
                    }
                    self.bumpe()?;
                    return Some((
                        Pattern::Array(list, Some((Box::new(pat.0), pat.1))),
                        self.new_span(start, self.span_end()),
                    ));
                }
                _ => {
                    let pat = self.parse_pat()?;
                    list.push(Some(pat));
                    match self.current() {
                        Token::Comma => {
                            self.bumpe()?;
                        }
                        Token::RSquare => {}
                        _ => {
                            self.error(ParsingError::new(
                                self.span(),
                                PET::wrong_token(
                                    ExpectedToken::OneOfTwo(Token::Comma, Token::RSquare),
                                    self.current().clone(),
                                ),
                            ));
                            return None;
                        }
                    }
                }
            }
        }
    }

    fn parse_atom(&mut self) -> Option<Spanned<Expr>> {
        let expr = match self.current() {
            Token::Identifier(ident) => Expr::Identifier((Ident(ident.clone()), self.span())),
            Token::Null => Expr::Literal((Literal::Null, self.span())),
            Token::HexLiteral(num) | Token::DecLiteral(num) => {
                Expr::Literal((Literal::Integer(*num), self.span()))
            }
            Token::FloatLiteral(num) => Expr::Literal((Literal::Float(*num), self.span())),
            Token::String(string) => Expr::Literal((Literal::String(string.clone()), self.span())),
            Token::TemplateString(template) => {
                let mut templates = Vec::new();

                let mut errors = Vec::new();

                for (template, span) in template {
                    templates.push(match template {
                        lexer::TemplateStringFragment::String(string) => {
                            (TemplateStringFragmentExpr::Literal(string.clone()), *span)
                        }
                        lexer::TemplateStringFragment::Placeholder(items) => {
                            let mut parser = Parser {
                                tokens: items,
                                cursor: 0,
                                errors: Vec::new(),
                            };

                            let expr = parser.parse_expr();
                            if !parser.is_empty() {
                                errors.push(ParsingError::new(
                                    *span,
                                    PET::TemplateStringPlaceholderRemainingTokens,
                                ));
                            }
                            errors.append(&mut parser.errors);
                            let expr = if let Some(expr) = expr {
                                expr
                            } else {
                                continue;
                            };
                            (TemplateStringFragmentExpr::Expr(expr.0), expr.1)
                        }
                    })
                }
                self.errors.append(&mut errors);
                Expr::Literal((Literal::Template(templates), self.span()))
            }
            Token::LSquare => {
                // array literal
                todo!()
            }
            Token::LCurly => {
                // object literal
                todo!()
            }
            Token::Function => {
                // function
                todo!()
            }
            Token::LParen => {
                let start = self.span_start();
                self.bumpe()?;
                let expr = self.parse_expr()?;
                match self.current() {
                    Token::RParen => {
                        self.bumpe()?;
                    }
                    Token::RSquare | Token::RCurly => {
                        self.error(ParsingError::new(
                            self.span(),
                            PET::MismatchedDelimiter {
                                expected: Token::RParen,
                                found: self.current().clone(),
                            },
                        ));
                        return None;
                    }
                    other => {
                        self.error(ParsingError::new(
                            self.span(),
                            PET::wrong_token(ExpectedToken::Token(Token::RParen), other.clone()),
                        ));
                        return None;
                    }
                }
                let end = self.prev_span_end();
                return Some((
                    Expr::Parenthesized(Box::new(expr)),
                    self.new_span(start, end),
                ));
            }
            _ => {
                self.error(ParsingError::new(
                    self.span(),
                    PET::wrong_token(
                        ExpectedToken::TokenType(Cow::Borrowed("Expression atom")),
                        self.current().clone(),
                    ),
                ));
                return None;
            }
        };
        self.bumpe()?;
        Some((expr, self.prev_span()))
    }

    fn parse_expr(&mut self) -> Option<Spanned<Expr>> {
        self.parse_expr_bp(0)
    }
}

// Pratt parsing
impl Parser<'_> {
    fn parse_expr_bp(&mut self, bp: u8) -> Option<Spanned<Expr>> {
        let mut lhs = match prefix_bp(self.current()) {
            Some(((), r_bp)) => {
                let opspan = self.span();
                let token = self.current().clone();
                self.bumpe()?;
                let expr = self.parse_expr_bp(r_bp)?;
                apply_prefix_op(&token, opspan, expr)
            }
            None => self.parse_atom()?,
        };
        loop {
            if let Some((l_bp, ())) = postfix_bp(self.current()) {
                if l_bp < bp {
                    break;
                }
                lhs = apply_postfix_op(self.current(), self.span(), lhs);
                self.bumpe()?;
                continue;
            }
            if let Some((l_bp, r_bp)) = infix_bp(self.current()) {
                if l_bp < bp {
                    break;
                }
                let curr = self.current().clone();
                let opspan = self.span();
                self.bumpe()?;
                let rhs = self.parse_expr_bp(r_bp)?;
                lhs = apply_infix_op(&curr, opspan, lhs, rhs);
                continue;
            }
            break;
        }

        Some(lhs)
    }
}

fn prefix_bp(t: &Token) -> Option<((), u8)> {
    match t {
        Token::PlusPlus
        | Token::MinusMinus
        | Token::Plus
        | Token::Minus
        | Token::Exclamation
        | Token::Tilde
        | Token::Typeof
        | Token::InstanceOf => Some(((), 100)),
        _ => None,
    }
}

fn apply_prefix_op(t: &Token, token_span: Span, expr: Spanned<Expr>) -> Spanned<Expr> {
    let exprspan = (token_span.start..expr.1.end).into();
    let prefix_op = match t {
        Token::PlusPlus => PrefixOp::PreInc,
        Token::MinusMinus => PrefixOp::PreDec,
        Token::Plus => PrefixOp::UnaryPlus,
        Token::Minus => PrefixOp::Negate,
        Token::Exclamation => PrefixOp::Not,
        Token::Tilde => PrefixOp::BitNot,
        Token::Typeof => PrefixOp::Typeof,
        Token::InstanceOf => PrefixOp::Instanceof,
        _ => panic!(
            "Internal compiler error. apply_prefix_op called on non-prefix op: {:?}",
            t
        ),
    };
    (
        Expr::UnaryPrefix {
            op: (prefix_op, token_span),
            expr: Box::new(expr),
        },
        exprspan,
    )
}

fn infix_bp(t: &Token) -> Option<(u8, u8)> {
    match t {
        Token::Asterisk | Token::Slash | Token::Percent => Some((155, 150)),
        Token::Plus | Token::Minus => Some((145, 140)),
        Token::Shl | Token::Shr | Token::ShrUnsigned => Some((135, 130)),
        Token::Ampersand => Some((125, 120)),
        Token::Caret => Some((115, 110)),
        Token::Pipe => Some((105, 100)),
        Token::Eqeq | Token::Neq | Token::LT | Token::GT | Token::LTE | Token::GTE => {
            Some((95, 90))
        }
        Token::DoubleAmpersand => Some((85, 84)),
        Token::DoublePipe => Some((83, 82)),
        Token::Eq
        | Token::PlusEquals
        | Token::MinusEquals
        | Token::AsteriskEquals
        | Token::SlashEquals
        | Token::PercentEquals
        | Token::AmpersandEquals
        | Token::PipeEquals
        | Token::CaretEquals
        | Token::ShlEquals
        | Token::ShrEquals
        | Token::ShrUnsignedEquals => Some((70, 75)),
        _ => None,
    }
}
fn apply_infix_op(
    t: &Token,
    token_span: Span,
    lexpr: Spanned<Expr>,
    rexpr: Spanned<Expr>,
) -> Spanned<Expr> {
    let exprspan = (lexpr.1.start..rexpr.1.end).into();
    let infix_op = match t {
        Token::Asterisk => InfixOp::Mul,
        Token::Slash => InfixOp::Div,
        Token::Percent => InfixOp::Mod,
        Token::Plus => InfixOp::Add,
        Token::Minus => InfixOp::Sub,
        Token::Shl => InfixOp::Shl,
        Token::Shr => InfixOp::Shr,
        Token::ShrUnsigned => InfixOp::ShrUnsigned,
        Token::Ampersand => InfixOp::BitAnd,
        Token::Caret => InfixOp::BitXor,
        Token::Pipe => InfixOp::BitOr,
        Token::Eqeq => InfixOp::Eqeq,
        Token::Neq => InfixOp::NotEq,
        Token::LT => InfixOp::LArrow,
        Token::GT => InfixOp::RArrow,
        Token::LTE => InfixOp::LTE,
        Token::GTE => InfixOp::GTE,
        Token::DoubleAmpersand => InfixOp::And,
        Token::DoublePipe => InfixOp::Or,
        Token::Eq => InfixOp::Assign,
        Token::PlusEquals => InfixOp::AddAssign,
        Token::MinusEquals => InfixOp::SubAssign,
        Token::AsteriskEquals => InfixOp::MulAssign,
        Token::SlashEquals => InfixOp::DivAssign,
        Token::PercentEquals => InfixOp::ModAssign,
        Token::AmpersandEquals => InfixOp::BitAndAssign,
        Token::PipeEquals => InfixOp::BitOrAssign,
        Token::CaretEquals => InfixOp::BitXorAssign,
        Token::ShlEquals => InfixOp::ShlAssign,
        Token::ShrEquals => InfixOp::ShrAssign,
        Token::ShrUnsignedEquals => InfixOp::ShrUnsignedAssign,
        _ => panic!("Internal compiler error. apply_infix_op called on non-infix op"),
    };
    (
        Expr::Infix {
            left: Box::new(lexpr),
            right: Box::new(rexpr),
            op: (infix_op, token_span),
        },
        exprspan,
    )
}
fn postfix_bp(t: &Token) -> Option<(u8, ())> {
    match t {
        Token::PlusPlus | Token::MinusMinus => Some((165, ())),
        _ => None,
    }
}

fn apply_postfix_op(t: &Token, token_span: Span, expr: Spanned<Expr>) -> Spanned<Expr> {
    let exprspan = (token_span.start..expr.1.end).into();
    let postfix_op = match t {
        Token::PlusPlus => PostfixOp::PostInc,
        Token::MinusMinus => PostfixOp::PostDec,
        _ => panic!("Internal compiler error. apply_postfix_op called on non-postfix op"),
    };
    (
        Expr::UnaryPostfix {
            op: (postfix_op, token_span),
            expr: Box::new(expr),
        },
        exprspan,
    )
}
