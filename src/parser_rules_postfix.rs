use crate::parser::BinaryOperator;
use crate::parser::Error as ParserError;
use crate::parser::{Ast, Parser};
use crate::scanner::{Token, TokenType};
use std::fmt;
use std::sync::Arc;

type CheckFn = dyn Fn(&mut Parser) -> bool;
type ParseFn = dyn Fn(&mut Parser, Ast) -> Result<Ast, ParserError>;

#[derive(Clone)]
pub struct PostfixRule {
    pub id: String,
    pub advance_token: bool,
    pub rule: Arc<CheckFn>,
    pub parse: Arc<ParseFn>,
}

impl fmt::Debug for PostfixRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParserRule")
            .field("id", &self.id)
            .field("advance_token", &self.advance_token)
            .finish()
    }
}

impl PostfixRule {
    pub fn get_default_rules() -> Vec<PostfixRule> {
        vec![
            PostfixRule {
                id: "DotExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, vec!['D', 'O', 'T']))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Dot {
                        accessor: Box::new(ast),
                        access: Box::new(parser.parse()?),
                    })
                }),
            },
            PostfixRule {
                id: "ArrIndex".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser
                        .check(Token(TokenType::Operator, "LEFT_BRACKET".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    let access = parser.parse()?;

                    if !parser.match_operator("RIGHT_BRACKET") {
                        return Err(ParserError::TokenMismatch);
                    }

                    Ok(Ast::Dot {
                        accessor: Box::new(ast),
                        access: Box::new(access),
                    })
                }),
            },
            PostfixRule {
                id: "PlusOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "PLUS".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::Add,
                    })
                }),
            },
            PostfixRule {
                id: "MinusOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "MINUS".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::Minus,
                    })
                }),
            },
            PostfixRule {
                id: "MulOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "STAR".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::Multiply,
                    })
                }),
            },
            PostfixRule {
                id: "DivOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "SLASH".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::Divide,
                    })
                }),
            },
            PostfixRule {
                id: "EqOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "EQUALITY".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::Equals,
                    })
                }),
            },
            PostfixRule {
                id: "GtOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "MORE_THAN".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::GreaterThan,
                    })
                }),
            },
            PostfixRule {
                id: "GtEqOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "MORE_EQ".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    let right = parser.parse()?;
                    Ok(Ast::Binary {
                        left: Box::new(Ast::Binary {
                            left: Box::new(ast.clone()),
                            right: Box::new(right.clone()),
                            operator: BinaryOperator::GreaterThan,
                        }),
                        right: Box::new(Ast::Binary {
                            left: Box::new(ast),
                            right: Box::new(right),
                            operator: BinaryOperator::Equals,
                        }),
                        operator: BinaryOperator::Add,
                    })
                }),
            },
            PostfixRule {
                id: "LtOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "LESS_THAN".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::LessThan,
                    })
                }),
            },
            PostfixRule {
                id: "LtEqOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "LESS_EQ".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    let right = parser.parse()?;
                    Ok(Ast::Binary {
                        left: Box::new(Ast::Binary {
                            left: Box::new(ast.clone()),
                            right: Box::new(right.clone()),
                            operator: BinaryOperator::LessThan,
                        }),
                        right: Box::new(Ast::Binary {
                            left: Box::new(ast),
                            right: Box::new(right),
                            operator: BinaryOperator::Equals,
                        }),
                        operator: BinaryOperator::Add,
                    })
                }),
            },
            PostfixRule {
                id: "ModOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "MOD".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Binary {
                        left: Box::new(ast),
                        right: Box::new(parser.parse()?),
                        operator: BinaryOperator::Modulo,
                    })
                }),
            },
            PostfixRule {
                id: "FunCall".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser
                        .check(Token(TokenType::Operator, "LEFT_PAREN".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    let mut args: Vec<Ast> = vec![];

                    if !parser.check(Token(TokenType::Operator, "RIGHT_PAREN".chars().collect())) {
                        loop {
                            args.push(parser.parse()?);

                            if !parser.match_operator("COMMA") {
                                break;
                            }
                        }
                    }

                    if !parser.match_operator("RIGHT_PAREN") {
                        return Err(ParserError::TokenMismatch);
                    }

                    Ok(Ast::Call {
                        what: Box::new(ast),
                        args,
                    })
                }),
            },
            PostfixRule {
                id: "SetOp".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "EQUALS".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    Ok(Ast::Set {
                        name: Box::new(ast),
                        value: Box::new(parser.parse()?),
                    })
                }),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::{Ast, BinaryOperator, Parser, Value};

    #[test]
    fn test_dot() {
        let mut p = Parser::new("a.b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Dot {
                accessor: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                access: Box::new(Ast::Value(Value::Ref("b".to_string())))
            }]
        );
    }

    #[test]
    fn test_arr_index() {
        let mut p = Parser::new("a[b]".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Dot {
                accessor: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                access: Box::new(Ast::Value(Value::Ref("b".to_string())))
            }]
        );
    }

    #[test]
    fn test_add() {
        let mut p = Parser::new("a + b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::Add
            }]
        );
    }

    #[test]
    fn test_minus() {
        let mut p = Parser::new("a - b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::Minus
            }]
        );
    }

    #[test]
    fn test_multiply() {
        let mut p = Parser::new("a * b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::Multiply
            }]
        );
    }

    #[test]
    fn test_divide() {
        let mut p = Parser::new("a / b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::Divide
            }]
        );
    }

    #[test]
    fn test_equals() {
        let mut p = Parser::new("a == b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::Equals
            }]
        );
    }

    #[test]
    fn test_greater_than() {
        let mut p = Parser::new("a > b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::GreaterThan
            }]
        );
    }

    #[test]
    fn test_greater_than_or_equal() {
        let mut p = Parser::new("a >= b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        let a = Box::new(Ast::Value(Value::Ref("a".to_string())));
        let b = Box::new(Ast::Value(Value::Ref("b".to_string())));

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Binary {
                    left: a.clone(),
                    right: b.clone(),
                    operator: BinaryOperator::GreaterThan
                }),
                right: Box::new(Ast::Binary {
                    left: a,
                    right: b,
                    operator: BinaryOperator::Equals
                }),
                operator: BinaryOperator::Add
            }]
        );
    }

    #[test]
    fn test_less_than() {
        let mut p = Parser::new("a < b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::LessThan
            }]
        );
    }

    #[test]
    fn test_less_than_or_equal() {
        let mut p = Parser::new("a <= b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        let a = Box::new(Ast::Value(Value::Ref("a".to_string())));
        let b = Box::new(Ast::Value(Value::Ref("b".to_string())));

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Binary {
                    left: a.clone(),
                    right: b.clone(),
                    operator: BinaryOperator::LessThan
                }),
                right: Box::new(Ast::Binary {
                    left: a,
                    right: b,
                    operator: BinaryOperator::Equals
                }),
                operator: BinaryOperator::Add
            }]
        );
    }

    #[test]
    fn test_modulo() {
        let mut p = Parser::new("a % b".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Binary {
                left: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                right: Box::new(Ast::Value(Value::Ref("b".to_string()))),
                operator: BinaryOperator::Modulo
            }]
        );
    }

    #[test]
    fn test_call_no_args() {
        let mut p = Parser::new("a()".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Call {
                what: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                args: vec![]
            }]
        )
    }

    #[test]
    fn test_call_one_arg() {
        let mut p = Parser::new("a(1)".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Call {
                what: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                args: vec![Ast::Value(Value::Int(1))]
            }]
        )
    }

    #[test]
    fn test_call_two_args() {
        let mut p = Parser::new("a(1,2)".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Call {
                what: Box::new(Ast::Value(Value::Ref("a".to_string()))),
                args: vec![Ast::Value(Value::Int(1)), Ast::Value(Value::Int(2))]
            }]
        )
    }

    #[test]
    fn test_set() {
        let mut p = Parser::new("x = 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Set {
                name: Box::new(Ast::Value(Value::Ref("x".to_string()))),
                value: Box::new(Ast::Value(Value::Int(0)))
            }]
        );
    }
}
