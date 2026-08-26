use crate::parser_rules::ParserRule;
use crate::parser_rules_postfix::PostfixRule;
use crate::scanner::{Scanner, ScannerError, Span, Token, TokenType};
use crate::scanner_rules::ScannerRule;
use rustc_hash::FxHashMap;

#[derive(Debug)]
pub struct MacroDef {
    pub arms: Vec<MacroArm>,
}

#[derive(Debug)]
pub struct MacroArm {
    pub pattern: Vec<Token>,
    pub expansion: Vec<Token>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    RuleNotFound,
    ScannerError(ScannerError),
    TokenMismatch(Token, Token),
    UnknownRule(Token),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::RuleNotFound => write!(f, "syntax rule not found"),
            Error::ScannerError(err) => write!(f, "scanner error: {}", err),
            Error::TokenMismatch(expected, actual) => {
                let exp_str = if expected.lexeme.is_empty() {
                    match expected.kind {
                        TokenType::Keyword => "keyword".to_string(),
                        TokenType::Identifier => "identifier".to_string(),
                        TokenType::Number => "number".to_string(),
                        TokenType::String => "string literal".to_string(),
                        TokenType::Operator => "operator".to_string(),
                        _ => format!("{:?}", expected.kind),
                    }
                } else if expected.kind == TokenType::Operator {
                    Token::friendly_operator_name(&expected.lexeme).to_string()
                } else {
                    format!("'{}'", expected.lexeme)
                };

                let act_str = actual.user_friendly_name();
                write!(f, "expected {}, found {}", exp_str, act_str)
            }
            Error::UnknownRule(token) => {
                if token.kind == TokenType::Special && token.lexeme == "EOF" {
                    write!(f, "unexpected end of file")
                } else {
                    write!(f, "unexpected {}", token.user_friendly_name())
                }
            }
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn span(&self) -> Option<Span> {
        match self {
            Error::TokenMismatch(_, actual) => Some(actual.span),
            Error::UnknownRule(token) => Some(token.span),
            _ => None,
        }
    }

    pub fn to_diagnostic(&self, source: Option<&str>, file: Option<&str>) -> crate::diagnostic::Diagnostic {
        match self {
            Error::ScannerError(err) => err.to_diagnostic(source, file),
            Error::TokenMismatch(expected, actual) => {
                let exp_str = if expected.lexeme.is_empty() {
                    match expected.kind {
                        TokenType::Keyword => "keyword".to_string(),
                        TokenType::Identifier => "identifier".to_string(),
                        TokenType::Number => "number".to_string(),
                        TokenType::String => "string literal".to_string(),
                        TokenType::Operator => "operator".to_string(),
                        _ => format!("{:?}", expected.kind),
                    }
                } else if expected.kind == TokenType::Operator {
                    Token::friendly_operator_name(&expected.lexeme).to_string()
                } else {
                    format!("'{}'", expected.lexeme)
                };

                let act_str = actual.user_friendly_name();
                let len = if actual.lexeme.is_empty() { 1 } else { actual.lexeme.len() };
                let mut diag = crate::diagnostic::Diagnostic::error(format!("expected {}, found {}", exp_str, act_str))
                    .with_location(actual.span.line, actual.span.column)
                    .with_length(len)
                    .with_label(format!("expected {}", exp_str));

                if let Some(src) = source {
                    diag = diag.with_source(src);
                }
                if let Some(f) = file {
                    diag = diag.with_file(f);
                }
                diag
            }
            Error::UnknownRule(token) => {
                let msg = if token.kind == TokenType::Special && token.lexeme == "EOF" {
                    "unexpected end of file".to_string()
                } else {
                    format!("unexpected {}", token.user_friendly_name())
                };
                let len = if token.lexeme.is_empty() { 1 } else { token.lexeme.len() };
                let mut diag = crate::diagnostic::Diagnostic::error(msg.clone())
                    .with_location(token.span.line, token.span.column)
                    .with_length(len)
                    .with_label(msg);

                if let Some(src) = source {
                    diag = diag.with_source(src);
                }
                if let Some(f) = file {
                    diag = diag.with_file(f);
                }
                diag
            }
            Error::RuleNotFound => {
                let mut diag = crate::diagnostic::Diagnostic::error("syntax error: rule not found");
                if let Some(src) = source {
                    diag = diag.with_source(src);
                }
                if let Some(f) = file {
                    diag = diag.with_file(f);
                }
                diag
            }
        }
    }
}

#[derive(Debug)]
pub struct Parser {
    /** Last token returned from scanner */
    pub(crate) last_token: Token,

    /** Set of top level rules */
    rules: Vec<ParserRule>,
    /** Set of postfix rule */
    rules_postfix: Vec<PostfixRule>,
    /** Internal scanner */
    scanner: Scanner,
    /** Macro definitions */
    macros: FxHashMap<String, MacroDef>,
}

impl Parser {
    #[must_use]
    pub fn new(src: String) -> Self {
        Self {
            last_token: Token {
                kind: TokenType::Special,
                lexeme: "".to_string(),
                span: Span { column: 0, line: 0 },
            },
            rules: ParserRule::get_default_rules(),
            rules_postfix: PostfixRule::get_default_rules(),
            scanner: Scanner::new(ScannerRule::get_default_rules(), src),
            macros: FxHashMap::default(),
        }
    }

    pub fn parse_all(&mut self) -> Result<Vec<Ast>, Error> {
        let mut buf: Vec<Ast> = vec![];

        loop {
            if self.last_token.kind == TokenType::Special
                && self.last_token.lexeme == "EOF".to_string()
            {
                break;
            }

            let tmp = self.parse()?;

            if tmp != Ast::Ignore && !matches!(tmp, Ast::Value(Value::String(_))) {
                buf.push(tmp);
            }
        }

        Ok(buf)
    }

    pub fn parse(&mut self) -> Result<Ast, Error> {
        let rules = self.rules.clone();
        let postfix = self.rules_postfix.clone();
        for rule in rules {
            if rule.rule.as_ref()(self) {
                if rule.advance_token {
                    self.advance()?;
                }

                let mut tmp = rule.parse.as_ref()(self)?;

                if tmp == Ast::Ignore {
                    return Ok(tmp);
                }

                loop {
                    let mut applied = false;

                    for postfix_rule in &postfix {
                        if postfix_rule.rule.as_ref()(self) {
                            if postfix_rule.advance_token {
                                self.advance()?;
                            }

                            let nested = postfix_rule.parse.as_ref()(self, tmp)?;

                            applied = true;
                            tmp = nested;
                            break;
                        }
                    }
                    if !applied {
                        break;
                    }
                }

                return Ok(tmp);
            }
        }

        Err(Error::UnknownRule(self.peek()?))
    }

    pub fn parse_rule(&mut self, id: &str) -> Result<Ast, Error> {
        let rule = self
            .rules
            .clone()
            .into_iter()
            .find(|rule| rule.id == id)
            .ok_or(Error::RuleNotFound)?;

        if rule.rule.as_ref()(self) {
            if rule.advance_token {
                self.advance()?;
            }

            return rule.parse.as_ref()(self);
        }

        Err(Error::RuleNotFound)
    }

    pub fn match_operator(&mut self, op: &str) -> bool {
        self.match_token(Token {
            kind: TokenType::Operator,
            lexeme: op.to_string(),
            span: Span { column: 0, line: 0 },
        })
    }

    pub fn match_keyword(&mut self, kw: &str) -> bool {
        self.match_token(Token {
            kind: TokenType::Keyword,
            lexeme: kw.to_string(),
            span: Span { column: 0, line: 0 },
        })
    }

    pub fn match_token(&mut self, tok: Token) -> bool {
        let check = self.check(tok.clone());

        if check {
            let _ = self.advance();
        }

        check
    }

    pub fn check(&mut self, tok: Token) -> bool {
        self.peek().unwrap() == tok
    }

    pub fn advance(&mut self) -> Result<Token, Error> {
        let last_token_buf = self.last_token.clone();

        let token = self.scanner.get_next().map_err(Error::ScannerError)?;

        self.last_token = token;

        Ok(last_token_buf.clone())
    }

    pub fn peek(&mut self) -> Result<Token, Error> {
        if self.last_token.kind == TokenType::Special && self.last_token.lexeme.is_empty() {
            let tok = self.scanner.get_next().map_err(Error::ScannerError)?;

            self.last_token = tok;
        }

        Ok(self.last_token.clone())
    }

    pub fn add_macro(&mut self, name: Token, macro_def: Vec<MacroArm>) {
        self.macros
            .insert(name.lexeme, MacroDef { arms: macro_def });
    }

    pub fn handle_macro(&mut self, id: &str, tokens: Vec<Token>) -> Result<(), Error> {
        let macro_def = self.macros.get(id).ok_or(Error::RuleNotFound)?;

        for arm in &macro_def.arms {
            let mut map = FxHashMap::default();
            let mut has_match = true;

            for (idx, tok) in tokens.iter().enumerate() {
                if arm.pattern.len() == 1
                    && arm.pattern[0].lexeme == "AT"
                    && arm.pattern[0].kind == TokenType::Operator
                {
                    has_match = true;
                    break;
                }

                if arm.pattern.len() < idx + 1 {
                    has_match = false;
                    break;
                }

                if arm.pattern[idx].lexeme.starts_with("@")
                    && arm.pattern[idx].kind == TokenType::Identifier
                {
                    map.insert(arm.pattern[idx].lexeme.clone(), tok);
                    continue;
                }

                has_match &= arm.pattern[idx] == *tok
            }

            if has_match {
                let result_stream: Vec<_> = if arm.pattern.len() == 1
                    && arm.pattern[0].lexeme == "AT"
                    && arm.pattern[0].kind == TokenType::Operator
                {
                    let mut buff = vec![];

                    for t in &arm.expansion.clone() {
                        if t.kind == TokenType::Operator && t.lexeme == "AT" {
                            buff.extend(tokens.clone());
                        } else {
                            buff.push(t.clone());
                        }
                    }

                    buff
                } else {
                    arm.expansion
                        .iter()
                        .map(|t| {
                            if t.kind == TokenType::Identifier && map.contains_key(&t.lexeme) {
                                return (*map.get(&t.lexeme).unwrap()).clone();
                            }

                            t.clone()
                        })
                        .collect()
                };

                self.scanner.append_stream(result_stream.clone());

                return Ok(());
            }
        }

        return Ok(());
    }

    pub fn expect_kind(&mut self, kind: TokenType) -> Result<Token, Error> {
        let token = self.peek()?;
        if token.kind == kind {
            let _ = self.advance();
            Ok(token)
        } else {
            Err(Error::TokenMismatch(
                Token {
                    kind,
                    lexeme: String::new(),
                    span: Span { line: 0, column: 0 },
                },
                token,
            ))
        }
    }

    pub fn expect_operator(&mut self, lexeme: &str) -> Result<Token, Error> {
        let token = self.advance()?;
        if token.kind == TokenType::Operator && token.lexeme == lexeme {
            Ok(token)
        } else {
            Err(Error::TokenMismatch(
                Token {
                    kind: TokenType::Operator,
                    lexeme: lexeme.to_string(),
                    span: Span { line: 0, column: 0 },
                },
                token,
            ))
        }
    }

    pub fn expect_keyword(&mut self, lexeme: &str) -> Result<Token, Error> {
        let token = self.advance()?;
        if token.kind == TokenType::Keyword && token.lexeme == lexeme {
            Ok(token)
        } else {
            Err(Error::TokenMismatch(
                Token {
                    kind: TokenType::Keyword,
                    lexeme: lexeme.to_string(),
                    span: Span { line: 0, column: 0 },
                },
                token,
            ))
        }
    }

    pub fn check_keyword(&mut self, lexeme: &str) -> bool {
        if let Ok(token) = self.peek() {
            token.kind == TokenType::Keyword && token.lexeme == lexeme
        } else {
            false
        }
    }

    pub fn check_operator(&mut self, lexeme: &str) -> bool {
        if let Ok(token) = self.peek() {
            token.kind == TokenType::Operator && token.lexeme == lexeme
        } else {
            false
        }
    }

    pub fn check_kind(&mut self, kind: TokenType) -> bool {
        if let Ok(token) = self.peek() {
            token.kind == kind
        } else {
            false
        }
    }
}

use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum Ast {
    Declare {
        name: String,
        value: Box<Ast>,
    },
    Value(Value),
    Object(Vec<(Ast, Ast)>),
    Return {
        value: Box<Ast>,
    },
    Raise {
        value: Box<Ast>,
    },
    Call {
        what: Box<Ast>,
        args: Vec<Ast>,
    },
    Binary {
        left: Box<Ast>,
        right: Box<Ast>,
        operator: BinaryOperator,
    },
    If {
        then_branch: Box<Ast>,
        else_branch: Option<Box<Ast>>,
        condition: Box<Ast>,
    },
    ContinueCode,
    BreakCode,
    Ignore,
    For {
        condition: Box<Ast>,
        body: Box<Ast>,
    },
    ForEach {
        iterable: Box<Ast>,
        var_name: String,
        body: Box<Ast>,
    },
    Block {
        code: Vec<Ast>,
    },
    Dot {
        accessor: Box<Ast>,
        access: Box<Ast>,
        resolve: bool,
    },
    Set {
        name: Box<Ast>,
        value: Box<Ast>,
    },
    Import {
        import_type: ImportType,
        import_map: Option<Vec<String>>,
        source: String,
        alias: Option<String>,
    },
    EnumDef {
        name: String,
        variants: Vec<EnumVariant>,
    },
    Match {
        target: Box<Ast>,
        arms: Vec<MatchArm>,
    },
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct MatchArm {
    pub pattern: MatchPattern,
    pub body: Box<Ast>,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum MatchPattern {
    Enum {
        name: String,
        tag: String,
        fields: Vec<String>,
    },
    Value(Value),
    Wildcard(Option<String>),
}

#[derive(Debug, Clone, Hash, PartialEq)]
pub struct EnumVariant {
    pub name: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImportType {
    Regular,
    Syntax,
    Translation,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd)]
pub enum BinaryOperator {
    Add,
    Minus,
    Multiply,
    Divide,
    Equals,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Modulo,
    BitAnd,
    BitOr,
    BitXor,
    BitSHL,
    BitSHR,
}

#[derive(Debug, Clone)]
pub enum Value {
    Int(i64),
    Double(f64),
    Bool(bool),
    String(String),
    Ref(String),
    Fun {
        args: Vec<String>,
        body: Box<Ast>,
    },
    Object(Vec<(Value, Value)>),
    EnumField {
        name: String,
        tag: String,
        fields: Vec<Ast>,
    },
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Int(v1), Value::Int(v2)) => v1 == v2,
            (Value::Double(v1), Value::Double(v2)) => v1.to_bits() == v2.to_bits(),
            (Value::Bool(v1), Value::Bool(v2)) => v1 == v2,
            (Value::String(v1), Value::String(v2)) => v1 == v2,
            (Value::Ref(v1), Value::Ref(v2)) => v1 == v2,
            (Value::Fun { args: a1, body: b1 }, Value::Fun { args: a2, body: b2 }) => {
                a1 == a2 && b1 == b2
            }
            (Value::Object(v1), Value::Object(v2)) => v1 == v2,
            (
                Value::EnumField {
                    name: v1_name,
                    tag: v1_tag,
                    fields: v1_fields,
                },
                Value::EnumField {
                    name: v2_name,
                    tag: v2_tag,
                    fields: v2_fields,
                },
            ) => v1_name == v2_name && v1_tag == v2_tag && v1_fields == v2_fields,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Value::Int(v) => {
                state.write_u8(0);
                v.hash(state);
            }
            Value::Double(v) => {
                state.write_u8(1);
                state.write_u64(v.to_bits());
            }
            Value::Bool(v) => {
                state.write_u8(2);
                v.hash(state);
            }
            Value::String(v) => {
                state.write_u8(3);
                v.hash(state);
            }
            Value::Ref(v) => {
                state.write_u8(4);
                v.hash(state);
            }
            Value::Fun { args, body } => {
                state.write_u8(5);
                args.hash(state);
                body.hash(state);
            }
            Value::Object(v) => {
                state.write_u8(6);
                v.hash(state);
            }
            Value::EnumField { name, tag, fields } => {
                name.as_str().hash(state);
                tag.as_str().hash(state);
                fields.hash(state);
            }
        }
    }
}
