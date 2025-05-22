use crate::lexer::{Span, Spanned};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Expr {
    Literal(Spanned<Literal>),
    Identifier(Spanned<Ident>),
    UnaryPrefix {
        op: (PrefixOp, Span),
        expr: Box<Spanned<Expr>>,
    },
    UnaryPostfix {
        expr: Box<Spanned<Expr>>,
        op: (PostfixOp, Span),
    },
    Infix {
        left: Box<Spanned<Expr>>,
        op: (InfixOp, Span),
        right: Box<Spanned<Expr>>,
    },
    Call {
        callee: Box<Spanned<Expr>>,
        arguments: Vec<Spanned<Expr>>,
    },
    Index {
        target: Box<Spanned<Expr>>,
        index: Box<Spanned<Expr>>,
    },
    ObjectLiteral(Vec<(Spanned<Ident>, Spanned<Expr>)>), // Object key-value pairs
    ArrayLiteral(Vec<Spanned<Expr>>),                    // Array of expressions
    Ternary {
        condition: Box<Spanned<Expr>>,
        then_expr: Box<Spanned<Expr>>,
        else_expr: Box<Spanned<Expr>>,
    },
    NewClass {
        class: Box<Spanned<Expr>>,
        arguments: Vec<Spanned<Expr>>,
    },
    Parenthesized(Box<Spanned<Expr>>),
    Err,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Ident(pub(crate) String);

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Literal {
    Null,
    Integer(i64),
    Float(f64),
    String(String),
    Template(Vec<Spanned<TemplateStringFragmentExpr>>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TemplateStringFragmentExpr {
    Literal(String),
    Expr(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Pattern {
    Object(Vec<(Spanned<Expr>, Option<Spanned<Pattern>>)>),
    // TODO: change to ident only
    Array(Vec<Option<Spanned<Pattern>>>, Option<Spanned<Box<Pattern>>>),
    Ident(Spanned<Ident>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PrefixOp {
    UnaryPlus,
    Negate,
    Not,
    BitNot,
    PreInc,
    PreDec,
    Typeof,
    Instanceof,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PostfixOp {
    PostInc,
    PostDec,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum InfixOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    NotEq,
    Eqeq,
    Assign,
    RArrow,
    GTE,
    LArrow,
    LTE,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    ShrUnsigned,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    ModAssign,
    BitAndAssign,
    BitOrAssign,
    BitXorAssign,
    ShlAssign,
    ShrAssign,
    ShrUnsignedAssign,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Stmt {
    ExprStmt(Spanned<Expr>),
    LetDecl {
        lhs: Spanned<Pattern>,
        rhs: Option<Spanned<Expr>>,
    },
    ConstDecl {
        lhs: Spanned<Pattern>,
        rhs: Option<Spanned<Expr>>,
    },
    If {
        condition: Spanned<Expr>,
        then_branch: Box<Spanned<Stmt>>,
        else_branch: Option<Box<Spanned<Stmt>>>,
    },
    While {
        condition: Spanned<Expr>,
        body: Box<Spanned<Stmt>>,
    },
    For {
        init: Option<Box<Spanned<Stmt>>>,
        condition: Option<Spanned<Expr>>,
        update: Option<Spanned<Expr>>,
        body: Box<Spanned<Stmt>>,
    },
    Return(Option<Spanned<Expr>>),
    Block(Spanned<Block>),
    Function {
        name: Spanned<Ident>,
        params: Spanned<Vec<Spanned<Pattern>>>,
        body: Spanned<Block>,
    },
    TryCatch {
        try_block: Spanned<Block>,
        catch_param: Option<Spanned<Pattern>>,
        catch_block: Box<Spanned<Block>>,
    },
    ClassDecl {
        name: Spanned<Ident>,
        methods: Vec<Spanned<FunctionDecl>>,
    },
    Empty,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Block {
    pub(crate) inner: Vec<Spanned<Stmt>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDecl {
    pub(crate) name: Option<Spanned<Ident>>,
    pub(crate) params: Vec<Spanned<Ident>>,
    pub(crate) body: Spanned<Block>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct File {
    pub(crate) stmts: Vec<Spanned<Stmt>>,
}
