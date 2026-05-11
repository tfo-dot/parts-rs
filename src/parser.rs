use crate::parser_rules::ParserRule;
use crate::parser_rules_postfix::PostfixRule;
use crate::scanner::{Scanner, ScannerError, Token, TokenType};
use crate::scanner_rules::ScannerRule;
use std::collections::HashMap;

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
    TokenMismatch,
    UnknownRule(Token),
}

#[derive(Debug)]
pub struct Parser {
    /** Last token returned from scanner */
    last_token: Token,

    /** Set of top level rules */
    rules: Vec<ParserRule>,
    /** Set of postfix rule */
    rules_postfix: Vec<PostfixRule>,
    /** Internal scanner */
    scanner: Scanner,
    /** Macro definitions */
    macros: HashMap<String, MacroDef>,
}

impl Parser {
    #[must_use]
    pub fn new(src: String) -> Self {
        Self {
            last_token: Token(TokenType::Special, vec![]),
            rules: ParserRule::get_default_rules(),
            rules_postfix: PostfixRule::get_default_rules(),
            scanner: Scanner::new(ScannerRule::get_default_rules(), src),
            macros: HashMap::new(),
        }
    }

    pub fn parse_all(&mut self) -> Result<Vec<Ast>, Error> {
        let mut buf: Vec<Ast> = vec![];

        loop {
            if self.last_token.0 == TokenType::Special && self.last_token.1 == vec!['E', 'O', 'F'] {
                break;
            }

            let tmp = self.parse()?;

            if tmp != Ast::Ignore {
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

        let temp = self.peek()?;
        Err(Error::UnknownRule(temp))
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
        self.match_token(Token(TokenType::Operator, op.chars().collect()))
    }

    pub fn match_keyword(&mut self, kw: &str) -> bool {
        self.match_token(Token(TokenType::Keyword, kw.chars().collect()))
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
        if self.last_token.0 == TokenType::Special && self.last_token.1 == vec![] {
            let tok = self.scanner.get_next().map_err(Error::ScannerError)?;

            self.last_token = tok;
        }

        Ok(self.last_token.clone())
    }

    pub fn add_macro(&mut self, name: Token, macro_def: Vec<MacroArm>) {
        self.macros
            .insert(name.1.into_iter().collect(), MacroDef { arms: macro_def });
    }

    pub fn handle_macro(&mut self, id: &str, tokens: Vec<Token>) -> Result<(), Error> {
        let macro_def = self.macros.get(id).ok_or(Error::RuleNotFound)?;

        for arm in &macro_def.arms {
            let mut has_match = true;
            let mut map = HashMap::new();

            for (idx, tok) in tokens.iter().enumerate() {
                if arm.pattern.len() < idx {
                    return Err(Error::RuleNotFound);
                }

                if arm.pattern[idx].1[0] == '@' && arm.pattern[idx].0 == TokenType::Identifier {
                    map.insert(arm.pattern[idx].1.clone(), tok);
                    continue;
                }

                has_match &= arm.pattern[idx] == *tok
            }

            if has_match {
                let result_stream: Vec<_> = arm
                    .expansion
                    .iter()
                    .map(|t| {
                        if t.0 == TokenType::Identifier && map.contains_key(&t.1) {
                            return (*map.get(&t.1).unwrap()).clone();
                        }

                        t.clone()
                    })
                    .collect();

                self.scanner.append_stream(result_stream.clone());

                return Ok(());
            } else {
                println!("Macro with no rule match");
            }
        }

        return Ok(());
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImportType {
    Regular,
    Syntax,
    Translation,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BinaryOperator {
    Add,
    Minus,
    Multiply,
    Divide,
    Equals,
    GreaterThan,
    LessThan,
    Modulo,
}

#[derive(Debug, Clone)]
pub enum Value {
    Int(i64),
    Double(f64),
    Bool(bool),
    String(String),
    Ref(String),
    Fun { args: Vec<String>, body: Box<Ast> },
    Object(Vec<(Value, Value)>),
    List(Vec<Value>),
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
            (Value::List(v1), Value::List(v2)) => v1 == v2,
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
            Value::List(v) => {
                state.write_u8(7);
                v.hash(state);
            }
        }
    }
}
