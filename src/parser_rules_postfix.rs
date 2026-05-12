use crate::parser::BinaryOperator;
use crate::parser::Error as ParserError;
use crate::parser::Value;
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
                        access: Box::new(parser.parse_rule("VarExpr")?),
                    })
                }),
            },
            PostfixRule {
                id: "ArrIndex".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "LEFT_BRACKET".chars().collect()))
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
                    parser.check(Token(TokenType::Operator, "LEFT_PAREN".chars().collect()))
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
            PostfixRule {
                id: "MacroCall".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "BANG".chars().collect()))
                }),
                parse: Arc::new(|parser, ast| {
                    let macro_name = if let Ast::Value(Value::Ref(name)) = ast {
                        name
                    } else {
                        return Err(ParserError::TokenMismatch);
                    };

                    if !parser.match_operator("LEFT_BRACE") {
                        return Err(ParserError::TokenMismatch);
                    }

                    let mut macro_call = vec![];

                    loop {
                        if parser.match_operator("RIGHT_BRACE") {
                            break;
                        }

                        if parser.match_operator("AT") {
                            if parser.peek()?.0 == TokenType::Identifier {
                                let mut temp = parser.advance()?;

                                let mut tmp_vec = vec!['@'];

                                tmp_vec.append(&mut temp.1);

                                temp.1 = tmp_vec;

                                macro_call.push(temp);
                                continue;
                            }
                        }

                        macro_call.push(parser.advance()?);
                    }

                    parser.handle_macro(&macro_name, macro_call)?;

                    Ok(Ast::Ignore)
                }),
            },
        ]
    }
}
