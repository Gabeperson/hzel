use crate::lexer::Spanned;

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Literal(Spanned<Literal>),
    Identifier(Spanned<Ident>),
    UnaryPrefix {
        op: Spanned<PrefixOp>,
        expr: Box<Spanned<Expr>>,
    },
    UnaryPostfix {
        expr: Box<Spanned<Expr>>,
        op: Spanned<PostfixOp>,
    },
    Infix {
        left: Box<Spanned<Expr>>,
        op: Spanned<InfixOp>,
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
    ObjectLiteral(Vec<(Spanned<Ident>, Spanned<Expr>)>),
    ArrayLiteral(Vec<Spanned<Expr>>),
    Ternary {
        condition: Box<Spanned<Expr>>,
        then_expr: Box<Spanned<Expr>>,
        else_expr: Box<Spanned<Expr>>,
    },
    NewClass {
        class: Class,
        arguments: Vec<Spanned<Expr>>,
    },
    Parenthesized(Box<Spanned<Expr>>),
    AsCast {
        left: Box<Spanned<Expr>>,
        to: Type,
    },
    Err,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Type {
    Vec(Box<Spanned<Type>>),
    HashMap(Box<Spanned<Type>>, Box<Spanned<Type>>),
    I64,
    F64,
    String,
    Class(Class),
    FnPtr(Spanned<Vec<Spanned<Type>>>, Option<Box<Spanned<Type>>>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Class(pub(crate) Ident);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Ident(pub(crate) String);

#[derive(Debug, Clone)]
pub(crate) enum Literal {
    Null,
    Integer(i64),
    Float(f64),
    String(String),
    Template(Vec<Spanned<TemplateStringFragmentExpr>>),
}

#[derive(Debug, Clone)]
pub(crate) enum TemplateStringFragmentExpr {
    Literal(String),
    Expr(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Pattern {
    Tuple(Vec<Option<Spanned<Pattern>>>),
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
    GT,
    GTE,
    LT,
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
#[derive(Debug, Clone)]
pub(crate) enum Stmt {
    ExprStmt(Spanned<Expr>),
    LetDecl {
        mutable: bool,
        lhs: Spanned<Pattern>,
        typ: Option<Spanned<Type>>,
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
        params: Spanned<Vec<(Spanned<Pattern>, Spanned<Type>)>>,
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

#[derive(Debug, Clone)]
pub(crate) struct Block {
    pub(crate) inner: Vec<Spanned<Stmt>>,
}

#[derive(Debug, Clone)]
pub struct FunctionDecl {
    pub(crate) name: Option<Spanned<Ident>>,
    pub(crate) params: Vec<Spanned<Ident>>,
    pub(crate) body: Spanned<Block>,
}

#[derive(Debug, Clone)]
pub(crate) struct File {
    pub(crate) stmts: Vec<Spanned<Stmt>>,
}
