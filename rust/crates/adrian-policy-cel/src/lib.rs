//! # adrian-policy-cel
//!
//! Common Expression Language (CEL) selector for role-based policy binding.
//! Used by `adrian-claims-engine` (AD FS CRL compat) and policy distribution.
//!
//! ## ADRs
//!
//! - ADR-030: Role-based policy binding
//! - ADR-101: AD FS claim rule language compatibility
//!
//! ## Implementation
//!
//! This crate ships a minimal hand-rolled CEL interpreter (no external CEL
//! crate dependency) that supports the subset of CEL used by the framework's
//! policy-binding and claims-engine code paths:
//!
//! - **Literals**: `true`, `false`, integers, single/double-quoted strings
//! - **Identifiers** with dot-member access: `host.os`, `user.groups`
//! - **Index access**: `arr[0]`, `map["key"]`
//! - **Binary ops**: `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`, `+`, `-`
//! - **Unary**: `!expr`
//! - **Method calls**: `.contains(x)`, `.size()`, `.startsWith(x)`,
//!   `.endsWith(x)`, `.lowerAscii()`, `.upperAscii()`
//! - **Parentheses** for grouping
//!
//! The evaluator takes a `serde_json::Value` as the evaluation context (the
//! "host facts" document per ADR-026).  Member access maps to JSON object
//! keys; index access maps to JSON array indices or object string keys.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;

use thiserror::Error;

// =========================================================================
// Error type
// =========================================================================

/// An error from CEL compilation or evaluation.
#[derive(Debug, Error)]
pub enum CelError {
    /// Compilation (parse) error.
    #[error("compile: {0}")]
    Compile(String),
    /// Evaluation error (e.g. type mismatch, undefined identifier).
    #[error("eval: {0}")]
    Eval(String),
}

// =========================================================================
// Public API
// =========================================================================

/// A compiled CEL expression.
///
/// Construct with [`CelSelector::compile`] and evaluate with
/// [`CelSelector::eval`].  The expression is parsed into an AST at compile
/// time so repeated evaluation against different fact contexts is cheap.
#[derive(Debug)]
pub struct CelSelector {
    ast: Expr,
    source: String,
}

impl CelSelector {
    /// Compile a CEL expression into an AST.
    ///
    /// Returns `Err(CelError::Compile(...))` on parse errors.  Compilation
    /// does NOT type-check the expression — type errors surface at eval
    /// time (matching the CEL spec's lazy typing model).
    pub fn compile(source: impl Into<String>) -> Result<Self, CelError> {
        let source = source.into();
        let tokens = tokenize(&source)?;
        let mut parser = Parser::new(&tokens);
        let ast = parser.parse_expr()?;
        if !parser.at_end() {
            return Err(CelError::Compile(format!(
                "unexpected token after expression: {:?}",
                parser.peek()
            )));
        }
        Ok(Self { ast, source })
    }

    /// Evaluate the compiled expression against a JSON host-facts document
    /// (ADR-026).  The returned `serde_json::Value` is the expression's
    /// result — typically a boolean for policy-binding expressions, but
    /// may be any JSON type.
    pub fn eval(&self, facts: &serde_json::Value) -> Result<serde_json::Value, CelError> {
        let ctx = EvalContext::from_root(facts);
        self.ast.eval(&ctx)
    }

    /// The original source string the selector was compiled from.  Useful
    /// for diagnostics and audit logs.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

// =========================================================================
// Tokenizer
// =========================================================================

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Literals
    Bool(bool),
    Int(i64),
    String(String),
    // Identifiers
    Ident(String),
    // Punctuation
    Dot,
    Comma,
    LParen,
    RParen,
    LBracket,
    RBracket,
    // Operators
    EqEq,   // ==
    NotEq,  // !=
    Lt,     // <
    Gt,     // >
    LtEq,   // <=
    GtEq,   // >=
    AndAnd, // &&
    OrOr,   // ||
    Not,    // !
    Plus,   // +
    Minus,  // -
    // End
    Eof,
}

fn tokenize(src: &str) -> Result<Vec<Token>, CelError> {
    let mut tokens = Vec::new();
    let mut chars = src.char_indices().peekable();
    while let Some(&(i, c)) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '.' => {
                chars.next();
                tokens.push(Token::Dot);
            }
            ',' => {
                chars.next();
                tokens.push(Token::Comma);
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '[' => {
                chars.next();
                tokens.push(Token::LBracket);
            }
            ']' => {
                chars.next();
                tokens.push(Token::RBracket);
            }
            '=' => {
                chars.next();
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Token::EqEq);
                } else {
                    return Err(CelError::Compile(format!(
                        "unexpected '=' at byte {i} (did you mean '=='?)"
                    )));
                }
            }
            '!' => {
                chars.next();
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Token::NotEq);
                } else {
                    tokens.push(Token::Not);
                }
            }
            '<' => {
                chars.next();
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Token::LtEq);
                } else {
                    tokens.push(Token::Lt);
                }
            }
            '>' => {
                chars.next();
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Token::GtEq);
                } else {
                    tokens.push(Token::Gt);
                }
            }
            '&' => {
                chars.next();
                if chars.peek().map(|&(_, c)| c) == Some('&') {
                    chars.next();
                    tokens.push(Token::AndAnd);
                } else {
                    return Err(CelError::Compile(format!(
                        "unexpected '&' at byte {i} (did you mean '&&'?)"
                    )));
                }
            }
            '|' => {
                chars.next();
                if chars.peek().map(|&(_, c)| c) == Some('|') {
                    chars.next();
                    tokens.push(Token::OrOr);
                } else {
                    return Err(CelError::Compile(format!(
                        "unexpected '|' at byte {i} (did you mean '||'?)"
                    )));
                }
            }
            '+' => {
                chars.next();
                tokens.push(Token::Plus);
            }
            '-' => {
                chars.next();
                tokens.push(Token::Minus);
            }
            '\'' | '"' => {
                let quote = c;
                chars.next(); // consume opening quote
                let mut s = String::new();
                let mut closed = false;
                while let Some(&(_, ch)) = chars.peek() {
                    if ch == quote {
                        chars.next();
                        closed = true;
                        break;
                    }
                    if ch == '\\' {
                        chars.next();
                        if let Some(&(_, esc)) = chars.peek() {
                            chars.next();
                            match esc {
                                'n' => s.push('\n'),
                                't' => s.push('\t'),
                                'r' => s.push('\r'),
                                '\\' => s.push('\\'),
                                '\'' => s.push('\''),
                                '"' => s.push('"'),
                                other => s.push(other),
                            }
                        }
                    } else {
                        s.push(ch);
                        chars.next();
                    }
                }
                if !closed {
                    return Err(CelError::Compile(format!(
                        "unterminated string starting at byte {i}"
                    )));
                }
                tokens.push(Token::String(s));
            }
            '0'..='9' => {
                let start = i;
                let mut s = String::new();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_ascii_digit() {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let n: i64 = s
                    .parse()
                    .map_err(|_| CelError::Compile(format!("invalid integer at byte {start}")))?;
                tokens.push(Token::Int(n));
            }
            'a'..='z' | 'A'..='Z' | '_' => {
                let mut s = String::new();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                match s.as_str() {
                    "true" => tokens.push(Token::Bool(true)),
                    "false" => tokens.push(Token::Bool(false)),
                    "null" => tokens.push(Token::Ident("null".into())),
                    _ => tokens.push(Token::Ident(s)),
                }
            }
            _ => {
                return Err(CelError::Compile(format!(
                    "unexpected character {c:?} at byte {i}"
                )));
            }
        }
    }
    tokens.push(Token::Eof);
    Ok(tokens)
}

// =========================================================================
// AST
// =========================================================================

#[derive(Debug, Clone)]
enum Expr {
    BoolLit(bool),
    IntLit(i64),
    StringLit(String),
    Ident(String),
    /// Receiver.method(args) — receiver is the LHS of the dot.
    MethodCall {
        receiver: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    /// A higher-order macro: `receiver.macro_name(var, predicate)`.
    /// Supported macros: `exists` (true if any element matches),
    /// `all` (true if all elements match), `filter` (array of matching
    /// elements), `map` (array of predicate results).
    Macro {
        receiver: Box<Expr>,
        name: String,
        var: String,
        predicate: Box<Expr>,
    },
    /// Member access: receiver.field
    Member {
        receiver: Box<Expr>,
        field: String,
    },
    /// Index access: container[index]
    Index {
        container: Box<Expr>,
        index: Box<Expr>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BinOp {
    EqEq,
    NotEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    AndAnd,
    OrOr,
    Plus,
    Minus,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum UnaryOp {
    Not,
    Neg,
}

// =========================================================================
// Parser (recursive descent)
// =========================================================================

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn at_end(&self) -> bool {
        matches!(self.peek(), Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if !matches!(t, Token::Eof) {
            self.pos += 1;
        }
        t
    }

    fn parse_expr(&mut self) -> Result<Expr, CelError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, CelError> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Token::OrOr) {
            self.advance();
            let rhs = self.parse_and()?;
            lhs = Expr::Binary {
                op: BinOp::OrOr,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, CelError> {
        let mut lhs = self.parse_comparison()?;
        while matches!(self.peek(), Token::AndAnd) {
            self.advance();
            let rhs = self.parse_comparison()?;
            lhs = Expr::Binary {
                op: BinOp::AndAnd,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_comparison(&mut self) -> Result<Expr, CelError> {
        let lhs = self.parse_additive()?;
        let op = match self.peek() {
            Token::EqEq => BinOp::EqEq,
            Token::NotEq => BinOp::NotEq,
            Token::Lt => BinOp::Lt,
            Token::Gt => BinOp::Gt,
            Token::LtEq => BinOp::LtEq,
            Token::GtEq => BinOp::GtEq,
            _ => return Ok(lhs),
        };
        self.advance();
        let rhs = self.parse_additive()?;
        Ok(Expr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        })
    }

    fn parse_additive(&mut self) -> Result<Expr, CelError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Plus => BinOp::Plus,
                Token::Minus => BinOp::Minus,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, CelError> {
        match self.peek() {
            Token::Not => {
                self.advance();
                let expr = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Not,
                    expr: Box::new(expr),
                })
            }
            Token::Minus => {
                self.advance();
                let expr = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Neg,
                    expr: Box::new(expr),
                })
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, CelError> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek() {
                Token::Dot => {
                    self.advance();
                    let Token::Ident(name) = self.advance() else {
                        return Err(CelError::Compile(format!(
                            "expected identifier after '.', got {:?}",
                            self.peek()
                        )));
                    };
                    if matches!(self.peek(), Token::LParen) {
                        // Method call
                        self.advance(); // consume (
                                        // Special-case the `exists(var, predicate)` macro
                                        // (and `all(var, predicate)`, `filter(var, predicate)`)
                                        // — the first argument is a variable binding (identifier),
                                        // not a sub-expression.  We capture it as a string and
                                        // store the predicate as the second arg.
                        let is_macro = matches!(name.as_str(), "exists" | "all" | "filter" | "map");
                        let mut args = Vec::new();
                        let mut macro_var: Option<String> = None;
                        if !matches!(self.peek(), Token::RParen) {
                            if is_macro {
                                // First arg: identifier (variable name).
                                if let Token::Ident(var_name) = self.advance() {
                                    macro_var = Some(var_name);
                                } else {
                                    return Err(CelError::Compile(format!(
                                        "{name}() macro: first arg must be an identifier (variable name)"
                                    )));
                                }
                                // Expect ','
                                if !matches!(self.peek(), Token::Comma) {
                                    return Err(CelError::Compile(format!(
                                        "{name}() macro: expected ',' after variable name"
                                    )));
                                }
                                self.advance();
                                // Second arg: predicate expression.
                                args.push(self.parse_expr()?);
                            } else {
                                args.push(self.parse_expr()?);
                                while matches!(self.peek(), Token::Comma) {
                                    self.advance();
                                    args.push(self.parse_expr()?);
                                }
                            }
                        }
                        if !matches!(self.peek(), Token::RParen) {
                            return Err(CelError::Compile(format!(
                                "expected ')' after method args, got {:?}",
                                self.peek()
                            )));
                        }
                        self.advance(); // consume )
                        if is_macro {
                            expr = Expr::Macro {
                                receiver: Box::new(expr),
                                name,
                                var: macro_var.unwrap_or_default(),
                                predicate: Box::new(
                                    args.into_iter().next().unwrap_or(Expr::BoolLit(true)),
                                ),
                            };
                        } else {
                            expr = Expr::MethodCall {
                                receiver: Box::new(expr),
                                method: name,
                                args,
                            };
                        }
                    } else {
                        // Field access
                        expr = Expr::Member {
                            receiver: Box::new(expr),
                            field: name,
                        };
                    }
                }
                Token::LBracket => {
                    self.advance();
                    let index = self.parse_expr()?;
                    if !matches!(self.peek(), Token::RBracket) {
                        return Err(CelError::Compile(format!(
                            "expected ']' after index, got {:?}",
                            self.peek()
                        )));
                    }
                    self.advance();
                    expr = Expr::Index {
                        container: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, CelError> {
        match self.advance() {
            Token::Bool(b) => Ok(Expr::BoolLit(b)),
            Token::Int(n) => Ok(Expr::IntLit(n)),
            Token::String(s) => Ok(Expr::StringLit(s)),
            Token::Ident(name) => Ok(Expr::Ident(name)),
            Token::LParen => {
                let expr = self.parse_expr()?;
                if !matches!(self.peek(), Token::RParen) {
                    return Err(CelError::Compile(format!(
                        "expected ')' after expression, got {:?}",
                        self.peek()
                    )));
                }
                self.advance();
                Ok(expr)
            }
            t => Err(CelError::Compile(format!(
                "unexpected token in primary position: {t:?}"
            ))),
        }
    }
}

// =========================================================================
// Evaluator
// =========================================================================

struct EvalContext<'a> {
    root: &'a serde_json::Value,
    /// Lexical variable bindings for macro predicates (e.g. the `c` in
    /// `claims.exists(c, c.type == 'group')`).  The binding is looked up
    /// here before falling back to the root context.
    bindings: Vec<(String, serde_json::Value)>,
}

impl<'a> EvalContext<'a> {
    fn from_root(root: &'a serde_json::Value) -> Self {
        Self {
            root,
            bindings: Vec::new(),
        }
    }

    fn with_binding(&self, name: String, value: serde_json::Value) -> Self {
        let mut new = Self {
            root: self.root,
            bindings: self.bindings.clone(),
        };
        new.bindings.push((name, value));
        new
    }

    fn lookup_binding(&self, name: &str) -> Option<&serde_json::Value> {
        self.bindings
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }
}

impl Expr {
    fn eval(&self, ctx: &EvalContext) -> Result<serde_json::Value, CelError> {
        match self {
            Expr::BoolLit(b) => Ok(serde_json::Value::Bool(*b)),
            Expr::IntLit(n) => Ok(serde_json::json!(*n)),
            Expr::StringLit(s) => Ok(serde_json::Value::String(s.clone())),
            Expr::Ident(name) => {
                if name == "null" {
                    return Ok(serde_json::Value::Null);
                }
                // Check macro bindings first (innermost scope).
                if let Some(v) = ctx.lookup_binding(name) {
                    return Ok(v.clone());
                }
                // Then the root context.
                if let serde_json::Value::Object(map) = ctx.root {
                    if let Some(v) = map.get(name) {
                        return Ok(v.clone());
                    }
                }
                Err(CelError::Eval(format!("undefined identifier: {name}")))
            }
            Expr::Member { receiver, field } => {
                let recv = receiver.eval(ctx)?;
                match &recv {
                    serde_json::Value::Object(map) => map
                        .get(field)
                        .cloned()
                        .ok_or_else(|| CelError::Eval(format!("no such field: {field}"))),
                    _ => Err(CelError::Eval(format!(
                        "cannot access field '{field}' on {}",
                        type_name(&recv)
                    ))),
                }
            }
            Expr::Index { container, index } => {
                let cont = container.eval(ctx)?;
                let idx = index.eval(ctx)?;
                match (&cont, &idx) {
                    (serde_json::Value::Array(arr), serde_json::Value::Number(n)) => {
                        let i = n.as_i64().ok_or_else(|| {
                            CelError::Eval(format!("index {n} is not an integer"))
                        })?;
                        let i = if i < 0 {
                            (arr.len() as i64 + i) as usize
                        } else {
                            i as usize
                        };
                        arr.get(i).cloned().ok_or_else(|| {
                            CelError::Eval(format!("index {i} out of bounds (len {})", arr.len()))
                        })
                    }
                    (serde_json::Value::Object(map), serde_json::Value::String(s)) => map
                        .get(s)
                        .cloned()
                        .ok_or_else(|| CelError::Eval(format!("no such key: {s}"))),
                    _ => Err(CelError::Eval(format!(
                        "cannot index {} with {}",
                        type_name(&cont),
                        type_name(&idx)
                    ))),
                }
            }
            Expr::MethodCall {
                receiver,
                method,
                args,
            } => eval_method_call(receiver, method, args, ctx),
            Expr::Macro {
                receiver,
                name,
                var,
                predicate,
            } => eval_macro(receiver, name, var, predicate, ctx),
            Expr::Binary { op, lhs, rhs } => {
                let l = lhs.eval(ctx)?;
                let r = rhs.eval(ctx)?;
                eval_binary(*op, &l, &r)
            }
            Expr::Unary { op, expr } => {
                let v = expr.eval(ctx)?;
                match op {
                    UnaryOp::Not => {
                        let b = as_bool(&v)?;
                        Ok(serde_json::Value::Bool(!b))
                    }
                    UnaryOp::Neg => {
                        let n = v.as_i64().ok_or_else(|| {
                            CelError::Eval(format!("cannot negate {}", type_name(&v)))
                        })?;
                        Ok(serde_json::json!(-n))
                    }
                }
            }
        }
    }
}

fn eval_method_call(
    receiver: &Expr,
    method: &str,
    args: &[Expr],
    ctx: &EvalContext,
) -> Result<serde_json::Value, CelError> {
    let recv = receiver.eval(ctx)?;
    let argv: Result<Vec<serde_json::Value>, CelError> = args.iter().map(|a| a.eval(ctx)).collect();
    let argv = argv?;
    match (method, &recv) {
        ("contains", serde_json::Value::String(s)) => {
            expect_args(method, &argv, 1)?;
            let needle = as_string(&argv[0])?;
            Ok(serde_json::Value::Bool(s.contains(&needle)))
        }
        ("contains", serde_json::Value::Array(arr)) => {
            expect_args(method, &argv, 1)?;
            Ok(serde_json::Value::Bool(arr.contains(&argv[0])))
        }
        ("startsWith", serde_json::Value::String(s)) => {
            expect_args(method, &argv, 1)?;
            let prefix = as_string(&argv[0])?;
            Ok(serde_json::Value::Bool(s.starts_with(&prefix)))
        }
        ("endsWith", serde_json::Value::String(s)) => {
            expect_args(method, &argv, 1)?;
            let suffix = as_string(&argv[0])?;
            Ok(serde_json::Value::Bool(s.ends_with(&suffix)))
        }
        ("size", serde_json::Value::String(s)) => {
            expect_args(method, &argv, 0)?;
            Ok(serde_json::json!(s.len() as i64))
        }
        ("size", serde_json::Value::Array(arr)) => {
            expect_args(method, &argv, 0)?;
            Ok(serde_json::json!(arr.len() as i64))
        }
        ("size", serde_json::Value::Object(map)) => {
            expect_args(method, &argv, 0)?;
            Ok(serde_json::json!(map.len() as i64))
        }
        ("lowerAscii", serde_json::Value::String(s)) => {
            expect_args(method, &argv, 0)?;
            Ok(serde_json::Value::String(s.to_ascii_lowercase()))
        }
        ("upperAscii", serde_json::Value::String(s)) => {
            expect_args(method, &argv, 0)?;
            Ok(serde_json::Value::String(s.to_ascii_uppercase()))
        }
        _ => Err(CelError::Eval(format!(
            "no method '{method}' on {}",
            type_name(&recv)
        ))),
    }
}

/// Evaluate a higher-order macro (`exists`, `all`, `filter`, `map`).
fn eval_macro(
    receiver: &Expr,
    name: &str,
    var: &str,
    predicate: &Expr,
    ctx: &EvalContext,
) -> Result<serde_json::Value, CelError> {
    let recv = receiver.eval(ctx)?;
    let arr = match &recv {
        serde_json::Value::Array(a) => a,
        _ => {
            return Err(CelError::Eval(format!(
                "{name}() requires an array, got {}",
                type_name(&recv)
            )));
        }
    };
    match name {
        "exists" => {
            for elem in arr {
                let sub_ctx = ctx.with_binding(var.to_string(), elem.clone());
                if as_bool(&predicate.eval(&sub_ctx)?)? {
                    return Ok(serde_json::Value::Bool(true));
                }
            }
            Ok(serde_json::Value::Bool(false))
        }
        "all" => {
            for elem in arr {
                let sub_ctx = ctx.with_binding(var.to_string(), elem.clone());
                if !as_bool(&predicate.eval(&sub_ctx)?)? {
                    return Ok(serde_json::Value::Bool(false));
                }
            }
            Ok(serde_json::Value::Bool(true))
        }
        "filter" => {
            let mut out = Vec::new();
            for elem in arr {
                let sub_ctx = ctx.with_binding(var.to_string(), elem.clone());
                if as_bool(&predicate.eval(&sub_ctx)?)? {
                    out.push(elem.clone());
                }
            }
            Ok(serde_json::Value::Array(out))
        }
        "map" => {
            let mut out = Vec::new();
            for elem in arr {
                let sub_ctx = ctx.with_binding(var.to_string(), elem.clone());
                out.push(predicate.eval(&sub_ctx)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        _ => Err(CelError::Eval(format!("unknown macro: {name}"))),
    }
}

fn eval_binary(
    op: BinOp,
    l: &serde_json::Value,
    r: &serde_json::Value,
) -> Result<serde_json::Value, CelError> {
    match op {
        BinOp::EqEq => Ok(serde_json::Value::Bool(json_eq(l, r))),
        BinOp::NotEq => Ok(serde_json::Value::Bool(!json_eq(l, r))),
        BinOp::AndAnd => {
            let lb = as_bool(l)?;
            if !lb {
                return Ok(serde_json::Value::Bool(false));
            }
            Ok(serde_json::Value::Bool(as_bool(r)?))
        }
        BinOp::OrOr => {
            let lb = as_bool(l)?;
            if lb {
                return Ok(serde_json::Value::Bool(true));
            }
            Ok(serde_json::Value::Bool(as_bool(r)?))
        }
        BinOp::Lt | BinOp::Gt | BinOp::LtEq | BinOp::GtEq => {
            let li = l.as_i64().ok_or_else(|| {
                CelError::Eval(format!(
                    "cannot compare {} with {}",
                    type_name(l),
                    type_name(r)
                ))
            })?;
            let ri = r.as_i64().ok_or_else(|| {
                CelError::Eval(format!(
                    "cannot compare {} with {}",
                    type_name(l),
                    type_name(r)
                ))
            })?;
            let b = match op {
                BinOp::Lt => li < ri,
                BinOp::Gt => li > ri,
                BinOp::LtEq => li <= ri,
                BinOp::GtEq => li >= ri,
                _ => unreachable!(),
            };
            Ok(serde_json::Value::Bool(b))
        }
        BinOp::Plus => {
            if let (Some(a), Some(b)) = (l.as_i64(), r.as_i64()) {
                return Ok(serde_json::json!(a + b));
            }
            if let (serde_json::Value::String(a), serde_json::Value::String(b)) = (l, r) {
                return Ok(serde_json::Value::String(format!("{a}{b}")));
            }
            Err(CelError::Eval(format!(
                "cannot add {} and {}",
                type_name(l),
                type_name(r)
            )))
        }
        BinOp::Minus => {
            let a = l
                .as_i64()
                .ok_or_else(|| CelError::Eval(format!("cannot subtract {}", type_name(r))))?;
            let b = r
                .as_i64()
                .ok_or_else(|| CelError::Eval(format!("cannot subtract {}", type_name(r))))?;
            Ok(serde_json::json!(a - b))
        }
    }
}

// ---- helpers ------------------------------------------------------------

fn type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn as_bool(v: &serde_json::Value) -> Result<bool, CelError> {
    v.as_bool()
        .ok_or_else(|| CelError::Eval(format!("expected bool, got {}", type_name(v))))
}

fn as_string(v: &serde_json::Value) -> Result<String, CelError> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        _ => Err(CelError::Eval(format!(
            "expected string, got {}",
            type_name(v)
        ))),
    }
}

fn json_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    // CEL `==` on numbers compares numerically (so 1 == 1.0 is true), but
    // our integer-only world makes a direct value comparison sufficient.
    a == b
}

fn expect_args(method: &str, argv: &[serde_json::Value], expected: usize) -> Result<(), CelError> {
    if argv.len() != expected {
        return Err(CelError::Eval(format!(
            "method '{method}' expects {expected} arg(s), got {}",
            argv.len()
        )));
    }
    Ok(())
}

// Silence unused-import warning for HashMap (kept for future extension).
#[allow(dead_code)]
fn _hashmap_anchor() -> HashMap<String, serde_json::Value> {
    HashMap::new()
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-policy-cel`.  These cover the real CEL
    //! interpreter — literal evaluation, member access, method calls,
    //! binary operators, and complex composite expressions.

    use super::*;

    // ---- compile / source round-trip -------------------------------------

    #[test]
    fn compile_returns_ok_for_valid_expression() {
        let sel = CelSelector::compile("host.os == 'linux'").expect("compile");
        assert_eq!(sel.source(), "host.os == 'linux'");
    }

    #[test]
    fn compile_accepts_owned_and_borrowed_strings() {
        let owned: String = "true".into();
        let _s1 = CelSelector::compile(owned).expect("owned");
        let _s2 = CelSelector::compile("borrowed".chars().collect::<String>().as_str())
            .expect("borrowed");
    }

    #[test]
    fn compile_rejects_unterminated_string() {
        let err = CelSelector::compile("host.os == 'linux").unwrap_err();
        assert!(matches!(err, CelError::Compile(_)));
        assert!(err.to_string().contains("unterminated"));
    }

    #[test]
    fn compile_rejects_unexpected_character() {
        let err = CelSelector::compile("host.os @ 'linux'").unwrap_err();
        assert!(matches!(err, CelError::Compile(_)));
    }

    #[test]
    fn cel_error_variants_render_messages() {
        let compile = CelError::Compile("syntax".into());
        let eval = CelError::Eval("no binding".into());
        assert_eq!(compile.to_string(), "compile: syntax");
        assert_eq!(eval.to_string(), "eval: no binding");
    }

    // ---- literal evaluation (true / false) -------------------------------

    #[test]
    fn eval_true_returns_bool_true() {
        let sel = CelSelector::compile("true").expect("compile");
        let result = sel.eval(&serde_json::Value::Null).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_false_returns_bool_false() {
        let sel = CelSelector::compile("false").expect("compile");
        let result = sel.eval(&serde_json::Value::Null).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(false));
    }

    #[test]
    fn eval_not_true_is_false() {
        let sel = CelSelector::compile("!true").expect("compile");
        let result = sel.eval(&serde_json::Value::Null).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(false));
    }

    // ---- member access + comparison (with context) -----------------------

    #[test]
    fn eval_member_access_and_string_equality() {
        let sel = CelSelector::compile("host.os == 'linux'").expect("compile");
        let facts = serde_json::json!({ "host": { "os": "linux" } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_member_access_returns_false_on_mismatch() {
        let sel = CelSelector::compile("host.os == 'linux'").expect("compile");
        let facts = serde_json::json!({ "host": { "os": "darwin" } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(false));
    }

    #[test]
    fn eval_undefined_identifier_returns_eval_error() {
        let sel = CelSelector::compile("missing.field").expect("compile");
        let facts = serde_json::json!({ "host": { "os": "linux" } });
        let err = sel.eval(&facts).unwrap_err();
        assert!(matches!(err, CelError::Eval(_)));
        assert!(err.to_string().contains("undefined identifier"));
    }

    // ---- method calls (contains, size, startsWith) -----------------------

    #[test]
    fn eval_string_contains_returns_true_on_match() {
        let sel = CelSelector::compile("host.name.contains('prod')").expect("compile");
        let facts = serde_json::json!({ "host": { "name": "prod-web-01" } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_array_contains_returns_true_on_member() {
        let sel = CelSelector::compile("user.groups.contains('admins')").expect("compile");
        let facts = serde_json::json!({ "user": { "groups": ["users", "admins"] } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_array_contains_returns_false_on_non_member() {
        let sel = CelSelector::compile("user.groups.contains('root')").expect("compile");
        let facts = serde_json::json!({ "user": { "groups": ["users", "admins"] } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(false));
    }

    #[test]
    fn eval_size_returns_array_length() {
        let sel = CelSelector::compile("user.groups.size()").expect("compile");
        let facts = serde_json::json!({ "user": { "groups": ["a", "b", "c"] } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::json!(3));
    }

    // ---- complex expressions (logical ops + comparisons + methods) -------

    #[test]
    fn eval_complex_and_expression() {
        let sel = CelSelector::compile("host.os == 'linux' && user.groups.contains('admins')")
            .expect("compile");
        let facts = serde_json::json!({
            "host": { "os": "linux" },
            "user": { "groups": ["admins", "users"] }
        });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_complex_or_expression_short_circuits() {
        let sel =
            CelSelector::compile("host.os == 'linux' || host.os == 'darwin'").expect("compile");
        let facts = serde_json::json!({ "host": { "os": "darwin" } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_complex_expression_with_parentheses() {
        let sel = CelSelector::compile(
            "(host.os == 'linux' && user.groups.contains('admins')) || host.is_bastion",
        )
        .expect("compile");
        let facts = serde_json::json!({
            "host": { "os": "darwin", "is_bastion": true },
            "user": { "groups": ["users"] }
        });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_not_equals_with_integers() {
        let sel = CelSelector::compile("host.cores != 1").expect("compile");
        let facts = serde_json::json!({ "host": { "cores": 4 } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_integer_comparison_with_gte() {
        let sel = CelSelector::compile("host.cores >= 4").expect("compile");
        let facts = serde_json::json!({ "host": { "cores": 8 } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    // ---- index access ----------------------------------------------------

    #[test]
    fn eval_array_index_access() {
        let sel = CelSelector::compile("user.groups[0] == 'admins'").expect("compile");
        let facts = serde_json::json!({ "user": { "groups": ["admins", "users"] } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn eval_object_index_access_with_string_key() {
        let sel = CelSelector::compile("config['env'] == 'prod'").expect("compile");
        let facts = serde_json::json!({ "config": { "env": "prod" } });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }
}
