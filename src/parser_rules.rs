use crate::{
    parser::Error as ParserError,
    parser::{Ast, Parser, Value},
    scanner::{Token, TokenType},
};
use std::{fmt, sync::Arc};

type CheckFn = dyn Fn(&mut Parser) -> bool;
type ParseFn = dyn Fn(&mut Parser) -> Result<Ast, ParserError>;

#[derive(Clone)]
pub struct ParserRule {
    pub id: String,
    pub advance_token: bool,
    pub rule: Arc<CheckFn>,
    pub parse: Arc<ParseFn>,
}

impl fmt::Debug for ParserRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParserRule")
            .field("id", &self.id)
            .field("advance_token", &self.advance_token)
            .finish()
    }
}

impl ParserRule {
    pub fn get_default_rules() -> Vec<ParserRule> {
        vec![
            ParserRule {
                id: "LetStmt".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, vec!['L', 'E', 'T']))
                }),
                parse: Arc::new(|parser| {
                    let identifier = parser.advance()?;

                    if identifier.0 != TokenType::Identifier {
                        println!("{:?}", 0);
                        return Err(ParserError::TokenMismatch);
                    }

                    let initial_value = if parser.match_operator("LEFT_PAREN") {
                        let token = parser.peek()?;

                        let mut args: Vec<String> = vec![];

                        if token.0 != TokenType::Operator
                            && token.1 != "RIGHT_PAREN".chars().collect::<Vec<char>>()
                        {
                            loop {
                                let arg = parser.advance()?;

                                if arg.0 != TokenType::Identifier {
                                    return Err(ParserError::TokenMismatch);
                                }

                                args.push(arg.1.iter().collect());

                                if parser.match_operator("COMMA") {
                                    continue;
                                }

                                if parser.check(Token(
                                    TokenType::Operator,
                                    "RIGHT_PAREN".chars().collect(),
                                )) {
                                    break;
                                }
                            }
                        }

                        if !parser.match_operator("RIGHT_PAREN") {
                            return Err(ParserError::TokenMismatch);
                        }

                        let body = if parser.match_operator("EQUALS") {
                            let value = Box::new(parser.parse()?);

                            Ast::Return { value }
                        } else {
                            parser.parse_rule("BlockExpr")?
                        };

                        Ast::Value(Value::Fun {
                            args,
                            body: Box::new(body),
                        })
                    } else {
                        if !parser.match_operator("EQUALS") {
                            return Err(ParserError::TokenMismatch);
                        }

                        parser.parse()?
                    };

                    Ok(Ast::Declare {
                        name: identifier.1.iter().collect(),
                        value: Box::new(initial_value),
                    })
                }),
            },
            ParserRule {
                id: "FunExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, vec!['F', 'U', 'N']))
                }),
                parse: Arc::new(|parser| {
                    if !parser.match_operator("LEFT_PAREN") {
                        return Err(ParserError::TokenMismatch);
                    }

                    let token = parser.peek()?;

                    let mut args: Vec<String> = vec![];

                    if token.0 != TokenType::Operator
                        && token.1 != "RIGHT_PAREN".chars().collect::<Vec<char>>()
                    {
                        loop {
                            let arg = parser.advance()?;

                            if arg.0 != TokenType::Identifier {
                                return Err(ParserError::TokenMismatch);
                            }

                            args.push(arg.1.iter().collect());

                            if parser.match_operator("COMMA") {
                                continue;
                            }

                            if parser
                                .check(Token(TokenType::Operator, "RIGHT_PAREN".chars().collect()))
                            {
                                break;
                            }
                        }
                    }

                    if !parser.match_operator("RIGHT_PAREN") {
                        return Err(ParserError::TokenMismatch);
                    }

                    let body = if parser.match_operator("EQUALS") {
                        Ast::Return {
                            value: Box::new(parser.parse()?),
                        }
                    } else {
                        parser.parse_rule("BlockExpr")?
                    };

                    Ok(Ast::Value(Value::Fun {
                        args,
                        body: Box::new(body),
                    }))
                }),
            },
            ParserRule {
                id: "IfExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| parser.check(Token(TokenType::Keyword, vec!['I', 'F']))),
                parse: Arc::new(|parser| {
                    let condition = parser.parse()?;
                    let then_branch = parser.parse()?;
                    let mut else_branch = None;

                    if parser.match_keyword("ELSE") {
                        else_branch = Some(Box::new(parser.parse()?));
                    }

                    Ok(Ast::If {
                        condition: Box::new(condition),
                        then_branch: Box::new(then_branch),
                        else_branch,
                    })
                }),
            },
            ParserRule {
                id: "ForExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, vec!['F', 'O', 'R']))
                }),
                parse: Arc::new(|parser| {
                    let condition = parser.parse()?;
                    let body = parser.parse()?;

                    Ok(Ast::For {
                        condition: Box::new(condition),
                        body: Box::new(body),
                    })
                }),
            },
            ParserRule {
                id: "BlockExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "LEFT_BRACE".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let mut body: Vec<Ast> = vec![];

                    loop {
                        let token = parser.peek()?;

                        if token.0 == TokenType::Operator
                            && token.1 == "RIGHT_BRACE".chars().collect::<Vec<char>>()
                        {
                            break;
                        }

                        body.push(parser.parse()?);
                    }

                    if !parser.match_operator("RIGHT_BRACE") {
                        return Err(ParserError::TokenMismatch);
                    }

                    Ok(Ast::Block { code: body })
                }),
            },
            ParserRule {
                id: "RaiseExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "RAISE".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    Ok(Ast::Raise {
                        value: Box::new(parser.parse()?),
                    })
                }),
            },
            ParserRule {
                id: "ReturnExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "RETURN".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    Ok(Ast::Return {
                        value: Box::new(parser.parse()?),
                    })
                }),
            },
            ParserRule {
                id: "Break".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "BREAK".chars().collect()))
                }),
                parse: Arc::new(|_parser| Ok(Ast::BreakCode)),
            },
            ParserRule {
                id: "Continue".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "CONTINUE".chars().collect()))
                }),
                parse: Arc::new(|_parser| Ok(Ast::ContinueCode)),
            },
            ParserRule {
                id: "TrueExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "TRUE".chars().collect()))
                }),
                parse: Arc::new(|_parser| Ok(Ast::Value(Value::Bool(true)))),
            },
            ParserRule {
                id: "FalseExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "FALSE".chars().collect()))
                }),
                parse: Arc::new(|_parser| Ok(Ast::Value(Value::Bool(false)))),
            },
            ParserRule {
                id: "NumExpr".to_string(),
                advance_token: false,
                rule: Arc::new(|parser| {
                    parser.peek().unwrap_or(Token(TokenType::Special, vec![])).0
                        == TokenType::Number
                }),
                parse: Arc::new(|parser| {
                    let raw = parser.advance()?;
                    let parsed: i64 = raw
                        .1
                        .iter()
                        .collect::<String>()
                        .parse()
                        .map_err(|_err| ParserError::TokenMismatch)?;
                    Ok(Ast::Value(Value::Int(parsed)))
                }),
            },
            ParserRule {
                id: "StringExpr".to_string(),
                advance_token: false,
                rule: Arc::new(|parser| {
                    parser.peek().unwrap_or(Token(TokenType::Special, vec![])).0
                        == TokenType::String
                }),
                parse: Arc::new(|parser| {
                    Ok(Ast::Value(Value::String(
                        parser.advance()?.1.iter().collect::<String>(),
                    )))
                }),
            },
            ParserRule {
                id: "VarExpr".to_string(),
                advance_token: false,
                rule: Arc::new(|parser| {
                    parser.peek().unwrap_or(Token(TokenType::Special, vec![])).0
                        == TokenType::Identifier
                }),
                parse: Arc::new(|parser| {
                    Ok(Ast::Value(Value::Ref(
                        parser.advance()?.1.iter().collect::<String>(),
                    )))
                }),
            },
            ParserRule {
                id: "GroupExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "LEFT_PAREN".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let val = parser.parse()?;

                    if !parser.match_operator("RIGHT_PAREN") {
                        return Err(ParserError::TokenMismatch);
                    }

                    Ok(val)
                }),
            },
            ParserRule {
                id: "ObjExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "OBJ_START".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let mut entries: Vec<[Value; 2]> = vec![];

                    if !parser.match_operator("OBJ_END") {
                        loop {
                            let key;

                            if let Ast::Value(key_value) = parser.parse()? {
                                key = key_value;
                            } else {
                                return Err(ParserError::TokenMismatch);
                            }

                            if !parser.match_operator("COLON") {
                                return Err(ParserError::TokenMismatch);
                            }

                            let val;

                            if let Ast::Value(value) = parser.parse()? {
                                val = value;
                            } else {
                                return Err(ParserError::TokenMismatch);
                            }

                            entries.push([key, val]);

                            if !parser.match_operator("COMMA") {
                                break;
                            }
                        }

                        if !parser.match_operator("OBJ_END") {
                            return Err(ParserError::TokenMismatch);
                        }
                    }

                    Ok(Ast::Value(Value::Object(entries)))
                }),
            },
            ParserRule {
                id: "ArrExpr".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "LEFT_BRACKET".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let mut entries: Vec<Value> = vec![];

                    if !parser.match_operator("RIGHT_BRACKET") {
                        loop {
                            let value;

                            if let Ast::Value(temp_value) = parser.parse()? {
                                value = temp_value;
                            } else {
                                return Err(ParserError::TokenMismatch);
                            }

                            entries.push(value);

                            if !parser.match_operator("COMMA") {
                                break;
                            }
                        }

                        if !parser.match_operator("RIGHT_BRACKET") {
                            return Err(ParserError::TokenMismatch);
                        }
                    }

                    Ok(Ast::Value(Value::List(entries)))
                }),
            },
            ParserRule {
                id: "SemicolonSkip".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Operator, "SEMICOLON".chars().collect()))
                }),
                parse: Arc::new(|_parser| Ok(Ast::Ignore)),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::{Ast, Parser, Value};

    #[test]
    fn test_semicolon() {
        let mut p = Parser::new(";".to_string());

        let res = p.parse_all();

        assert!(res.is_ok());

        let val = res.unwrap();

        assert_eq!(val.len(), 0);
    }

    #[test]
    fn test_array_empty() {
        let mut p = Parser::new("[]".to_string());

        let res = p.parse_all();

        assert!(res.is_ok());

        let val = res.unwrap();

        assert_eq!(val.len(), 1);

        if let Some(Ast::Value(Value::List(inner_arr))) = val.first() {
            assert_eq!(inner_arr.as_slice(), &[]);
        } else {
            panic!(
                "Expected Ast::Value(Value::List) at 0, got {:?}",
                val.first()
            );
        }
    }

    #[test]
    fn test_array_one_element() {
        let mut p = Parser::new("[false]".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        let val = res.unwrap();
        assert_eq!(val.len(), 1);

        if let Some(Ast::Value(Value::List(inner_arr))) = val.first() {
            assert_eq!(inner_arr.as_slice(), &[Value::Bool(false)]);
        } else {
            panic!(
                "Expected Ast::Value(Value::List) at 0, got {:?}",
                val.first()
            );
        }
    }

    #[test]
    fn test_array_two_elements() {
        let mut p = Parser::new("[false, true]".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        let val = res.unwrap();
        assert_eq!(val.len(), 1);

        if let Some(Ast::Value(Value::List(inner_arr))) = val.first() {
            assert_eq!(
                inner_arr.as_slice(),
                &[Value::Bool(false), Value::Bool(true)]
            );
        } else {
            panic!(
                "Expected Ast::Value(Value::List) at 0, got {:?}",
                val.first()
            );
        }
    }

    #[test]
    fn test_object_empty() {
        let mut p = Parser::new("|> <|".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        let val = res.unwrap();

        assert_eq!(val.len(), 1);

        if let Some(Ast::Value(Value::Object(inner_obj))) = val.first() {
            assert_eq!(inner_obj.clone(), Vec::<[Value; 2]>::new());
        } else {
            panic!(
                "Expected Ast::Value(Value::Object) at 0, got {:?}",
                val.first()
            );
        }
    }

    #[test]
    fn test_object_one_entry() {
        let mut p = Parser::new("|> expectFalse: false <|".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        let val = res.unwrap();
        assert_eq!(val.len(), 1);

        if let Some(Ast::Value(Value::Object(inner_obj))) = val.first() {
            assert_eq!(
                inner_obj.clone(),
                vec![[Value::Ref("expectFalse".to_string()), Value::Bool(false)]]
            );
        } else {
            panic!(
                "Expected Ast::Value(Value::Object) at 0, got {:?}",
                val.first()
            );
        }
    }

    #[test]
    fn test_object_two_entries() {
        let mut p = Parser::new("|> expectFalse: false, expectTrue: true <|".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        let val = res.unwrap();
        assert_eq!(val.len(), 1);

        if let Some(Ast::Value(Value::Object(inner_obj))) = val.first() {
            assert_eq!(
                inner_obj.clone(),
                vec![
                    [Value::Ref("expectFalse".to_string()), Value::Bool(false)],
                    [Value::Ref("expectTrue".to_string()), Value::Bool(true)]
                ]
            );
        } else {
            panic!(
                "Expected Ast::Value(Value::Object) at 0, got {:?}",
                val.first()
            );
        }
    }

    #[test]
    fn test_group() {
        let mut p = Parser::new("(false)".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::Value(Value::Bool(false))]);
    }

    #[test]
    fn test_var() {
        let mut p = Parser::new("x".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::Value(Value::Ref("x".to_string()))]);
    }

    #[test]
    fn test_string() {
        let mut p = Parser::new("`x`".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Value(Value::String("x".to_string()))]
        );
    }

    #[test]
    fn test_number() {
        let mut p = Parser::new("0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::Value(Value::Int(0))]);
    }

    #[test]
    fn test_false() {
        let mut p = Parser::new("false".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::Value(Value::Bool(false))]);
    }

    #[test]
    fn test_true() {
        let mut p = Parser::new("true".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::Value(Value::Bool(true))]);
    }

    #[test]
    fn test_continue() {
        let mut p = Parser::new("continue".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::ContinueCode]);
    }

    #[test]
    fn test_break() {
        let mut p = Parser::new("break".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::BreakCode]);
    }

    #[test]
    fn test_return_no_value() {
        let mut p = Parser::new("return;".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Return {
                value: Box::new(Ast::Ignore)
            }]
        );
    }

    #[test]
    fn test_return_with_value() {
        let mut p = Parser::new("return 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Return {
                value: Box::new(Ast::Value(Value::Int(0)))
            }]
        );
    }

    #[test]
    fn test_raise_no_value() {
        let mut p = Parser::new("raise;".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Raise {
                value: Box::new(Ast::Ignore)
            }]
        );
    }

    #[test]
    fn test_raise_with_value() {
        let mut p = Parser::new("raise 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Raise {
                value: Box::new(Ast::Value(Value::Int(0)))
            }]
        );
    }

    #[test]
    fn test_block_empty() {
        let mut p = Parser::new("{}".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(res.unwrap(), vec![Ast::Block { code: vec![] }]);
    }

    #[test]
    fn test_block_with_code() {
        let mut p = Parser::new("{ return 0 }".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Block {
                code: vec![Ast::Return {
                    value: Box::new(Ast::Value(Value::Int(0)))
                }]
            }]
        );
    }

    #[test]
    fn test_for() {
        let mut p = Parser::new("for true { return 0 }".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::For {
                condition: Box::new(Ast::Value(Value::Bool(true))),
                body: Box::new(Ast::Block {
                    code: vec![Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    }]
                })
            }]
        );
    }

    #[test]
    fn test_for_without_braces() {
        let mut p = Parser::new("for true return 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::For {
                condition: Box::new(Ast::Value(Value::Bool(true))),
                body: Box::new(Ast::Return {
                    value: Box::new(Ast::Value(Value::Int(0)))
                })
            }]
        );
    }

    #[test]
    fn test_if() {
        let mut p = Parser::new("if true { return 0 } else {return 1}".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::If {
                condition: Box::new(Ast::Value(Value::Bool(true))),
                then_branch: Box::new(Ast::Block {
                    code: vec![Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    }]
                }),
                else_branch: Some(Box::new(Ast::Block {
                    code: vec![Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(1)))
                    }]
                })),
            }]
        );
    }

    #[test]
    fn test_if_no_else() {
        let mut p = Parser::new("if true { return 0 }".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::If {
                condition: Box::new(Ast::Value(Value::Bool(true))),
                then_branch: Box::new(Ast::Block {
                    code: vec![Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    }]
                }),
                else_branch: None,
            }]
        );
    }

    #[test]
    fn test_fun_no_arguments_short() {
        let mut p = Parser::new("fun () = 0;".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Value(Value::Fun {
                args: vec![],
                body: Box::new(Ast::Return {
                    value: Box::new(Ast::Value(Value::Int(0)))
                })
            })]
        );
    }

    #[test]
    fn test_fun_no_arguments() {
        let mut p = Parser::new("fun () {return 0}".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Value(Value::Fun {
                args: vec![],
                body: Box::new(Ast::Block {
                    code: vec![Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    }]
                })
            })]
        );
    }

    #[test]
    fn test_fun_one_argument_short() {
        let mut p = Parser::new("fun (x) = 0;".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Value(Value::Fun {
                args: vec!["x".to_string()],
                body: Box::new(Ast::Return {
                    value: Box::new(Ast::Value(Value::Int(0)))
                })
            })]
        );
    }

    #[test]
    fn test_fun_one_argument() {
        let mut p = Parser::new("fun (x) {return 0}".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Value(Value::Fun {
                args: vec!["x".to_string()],
                body: Box::new(Ast::Block {
                    code: vec![Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    }]
                })
            })]
        );
    }

    #[test]
    fn test_fun_two_arguments_short() {
        let mut p = Parser::new("fun (x, y) = 0;".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Value(Value::Fun {
                args: vec!["x".to_string(), "y".to_string()],
                body: Box::new(Ast::Return {
                    value: Box::new(Ast::Value(Value::Int(0)))
                })
            })]
        );
    }

    #[test]
    fn test_fun_two_arguments() {
        let mut p = Parser::new("fun (x, y) {return 0}".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Value(Value::Fun {
                args: vec!["x".to_string(), "y".to_string()],
                body: Box::new(Ast::Block {
                    code: vec![Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    }]
                })
            })]
        );
    }

    #[test]
    fn test_let() {
        let mut p = Parser::new("let x = 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(Value::Int(0)))
            }]
        );
    }

    #[test]
    fn test_let_function_no_args_short() {
        let mut p = Parser::new("let x() = 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(Value::Fun {
                    args: vec![],
                    body: Box::new(Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    })
                }))
            }]
        );
    }

    #[test]
    fn test_let_function_no_args() {
        let mut p = Parser::new("let x() { return 0 }".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(Value::Fun {
                    args: vec![],
                    body: Box::new(Ast::Block {
                        code: vec![Ast::Return {
                            value: Box::new(Ast::Value(Value::Int(0)))
                        }]
                    })
                }))
            }]
        );
    }

    #[test]
    fn test_let_function_one_arg_short() {
        let mut p = Parser::new("let x(x) = 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(Value::Fun {
                    args: vec!["x".to_string()],
                    body: Box::new(Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    })
                }))
            }]
        );
    }

    #[test]
    fn test_let_function_one_arg() {
        let mut p = Parser::new("let x(x) { return 0 }".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(Value::Fun {
                    args: vec!["x".to_string()],
                    body: Box::new(Ast::Block {
                        code: vec![Ast::Return {
                            value: Box::new(Ast::Value(Value::Int(0)))
                        }]
                    })
                }))
            }]
        );
    }

    #[test]
    fn test_let_function_two_args_short() {
        let mut p = Parser::new("let x(x, y) = 0".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(Value::Fun {
                    args: vec!["x".to_string(), "y".to_string()],
                    body: Box::new(Ast::Return {
                        value: Box::new(Ast::Value(Value::Int(0)))
                    })
                }))
            }]
        );
    }

    #[test]
    fn test_let_function_two_args() {
        let mut p = Parser::new("let x(x, y) { return 0 }".to_string());
        let res = p.parse_all();
        assert!(res.is_ok());

        assert_eq!(
            res.unwrap(),
            vec![Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(Value::Fun {
                    args: vec!["x".to_string(), "y".to_string()],
                    body: Box::new(Ast::Block {
                        code: vec![Ast::Return {
                            value: Box::new(Ast::Value(Value::Int(0)))
                        }]
                    })
                }))
            }]
        );
    }
}
