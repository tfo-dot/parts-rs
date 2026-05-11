use crate::{
    parser::{Ast, Error as ParserError, ImportType, MacroArm, Parser, Value},
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
                id: "ImportStmt".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "IMPORT".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let mut import_type = ImportType::Regular;
                    let mut import_map = None;

                    if parser.match_keyword("SYNTAX") {
                        import_type = ImportType::Syntax;
                    } else if parser.match_keyword("TRANSLATION") {
                        import_type = ImportType::Translation;
                    }

                    if parser.match_operator("LEFT_BRACE") {
                        let mut identifiers: Vec<String> = vec![];

                        if !parser
                            .check(Token(TokenType::Operator, "RIGHT_BRACE".chars().collect()))
                        {
                            loop {
                                let identifier = parser.advance()?;

                                if identifier.0 != TokenType::Identifier {
                                    return Err(ParserError::TokenMismatch);
                                }

                                identifiers.push(identifier.1.iter().collect());

                                if !parser.match_operator("COMMA") {
                                    break;
                                }
                            }

                            if !parser.match_operator("RIGHT_BRACE") {
                                return Err(ParserError::TokenMismatch);
                            }

                            if !parser.match_keyword("FROM") {
                                return Err(ParserError::TokenMismatch);
                            }
                        }

                        import_map = Some(identifiers)
                    }

                    let source_token = parser.advance()?;

                    if source_token.0 != TokenType::String {
                        return Err(ParserError::TokenMismatch);
                    }

                    let mut alias = None;
                    if parser.match_keyword("AS") {
                        let alias_token = parser.advance()?;
                        if alias_token.0 != TokenType::Identifier {
                            return Err(ParserError::TokenMismatch);
                        }
                        alias = Some(alias_token.1.iter().collect());
                    }

                    Ok(Ast::Import {
                        import_type,
                        import_map,
                        source: source_token.1.iter().collect::<String>(),
                        alias,
                    })
                }),
            },
            ParserRule {
                id: "UseStmt".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "USE".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let import_type = if parser.match_keyword("SYNTAX") {
                        ImportType::Syntax
                    } else if parser.match_keyword("TRANSLATION") {
                        ImportType::Translation
                    } else {
                        return Err(ParserError::TokenMismatch);
                    };

                    let source_token = parser.advance()?;
                    if source_token.0 != TokenType::String {
                        return Err(ParserError::TokenMismatch);
                    }

                    if !parser.match_keyword("AS") {
                        return Err(ParserError::TokenMismatch);
                    }

                    let alias_token = parser.advance()?;
                    if alias_token.0 != TokenType::Identifier {
                        return Err(ParserError::TokenMismatch);
                    }

                    Ok(Ast::Import {
                        import_type,
                        import_map: None,
                        source: source_token.1.iter().collect(),
                        alias: Some(alias_token.1.iter().collect()),
                    })
                }),
            },
            ParserRule {
                id: "LetStmt".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "LET".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let identifier = parser.advance()?;

                    if identifier.0 != TokenType::Identifier {
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

                    return if parser.match_keyword("IN") {
                        return if let Ast::Value(Value::Ref(ref ref_val)) = condition {
                            let iter = parser.parse()?;

                            let body = parser.parse()?;

                            Ok(Ast::ForEach {
                                iterable: Box::new(iter),
                                var_name: ref_val.to_string(),
                                body: Box::new(body),
                            })
                        } else {
                            return Err(ParserError::TokenMismatch);
                        };
                    } else {
                        let body = parser.parse()?;

                        Ok(Ast::For {
                            condition: Box::new(condition),
                            body: Box::new(body),
                        })
                    };
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

                        let temp = parser.parse()?;
                        if temp != Ast::Ignore {
                            body.push(temp);
                        }
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

                    match raw.1.iter().filter(|&c| *c == '.').count() {
                        0 => {
                            let parsed: i64 = raw
                                .1
                                .iter()
                                .collect::<String>()
                                .parse()
                                .map_err(|_err| ParserError::TokenMismatch)?;
                            Ok(Ast::Value(Value::Int(parsed)))
                        }
                        1 => {
                            let parsed: f64 = raw
                                .1
                                .iter()
                                .collect::<String>()
                                .parse()
                                .map_err(|_err| ParserError::TokenMismatch)?;
                            Ok(Ast::Value(Value::Double(parsed)))
                        }
                        _ => Err(ParserError::TokenMismatch),
                    }
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
                    let mut entries: Vec<(Value, Value)> = vec![];

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

                            entries.push((key, val));

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
                id: "MacroDefinition".to_string(),
                advance_token: true,
                rule: Arc::new(|parser| {
                    parser.check(Token(TokenType::Keyword, "PART".chars().collect()))
                }),
                parse: Arc::new(|parser| {
                    let macro_name = parser.advance()?;

                    if macro_name.0 != TokenType::Identifier {
                        return Err(ParserError::TokenMismatch);
                    }

                    let mut arms: Vec<MacroArm> = vec![];

                    if !parser.match_operator("LEFT_BRACE") {
                        return Err(ParserError::TokenMismatch);
                    }

                    loop {
                        if parser.match_operator("RIGHT_BRACE") {
                            break;
                        }

                        let mut current_arm = MacroArm {
                            expansion: vec![],
                            pattern: vec![],
                        };

                        loop {
                            if !parser.match_operator("LEFT_PAREN") {
                                return Err(ParserError::TokenMismatch);
                            }

                            loop {
                                if parser.match_operator("AT") {
                                    if parser.peek()?.0 == TokenType::Identifier {
                                        let mut temp = parser.advance()?;

                                        let mut tmp_vec = vec!['@'];

                                        tmp_vec.append(&mut temp.1);

                                        temp.1 = tmp_vec;

                                        current_arm.pattern.push(temp);
                                        continue;
                                    }
                                }

                                if parser.match_operator("RIGHT_PAREN") {
                                    break;
                                }

                                current_arm.pattern.push(parser.advance()?);
                            }

                            break;
                        }

                        if !parser.match_operator("ARROW_LEFT") {
                            return Err(ParserError::TokenMismatch);
                        }

                        if !parser.match_operator("LEFT_BRACE") {
                            return Err(ParserError::TokenMismatch);
                        }

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

                                    current_arm.expansion.push(temp);
                                    continue;
                                }
                            }

                            current_arm.expansion.push(parser.advance()?);
                        }

                        arms.push(current_arm);
                    }

                    parser.add_macro(macro_name, arms);

                    Ok(Ast::Ignore)
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
