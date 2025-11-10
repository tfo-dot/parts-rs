use crate::parser_rules::ParserRule;
use crate::parser_rules_postfix::PostfixRule;
use crate::scanner::{Scanner, ScannerError, Token, TokenType};
use crate::scanner_rules::ScannerRule;

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
}

impl Parser {
    #[must_use]
    pub fn new(src: String) -> Self {
        Self {
            last_token: Token(TokenType::Special, vec![]),
            rules: ParserRule::get_default_rules(),
            rules_postfix: PostfixRule::get_default_rules(),
            scanner: Scanner::new(ScannerRule::get_default_rules(), src),
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
}

#[derive(Debug, Clone, PartialEq)]
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
    }
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Double(f64),
    Bool(bool),
    String(String),
    Ref(String),
    Fun { args: Vec<String>, body: Box<Ast> },
    Object(Vec<[Value; 2]>),
    List(Vec<Value>),
}