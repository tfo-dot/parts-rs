#[cfg(test)]
mod tests {

    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use parts::compiler::Compiler;
    use parts::compiler::OpCode;
    use parts::parser::Ast;
    use parts::parser::BinaryOperator;
    use parts::parser::Value as ParserValue;
    use parts::value::Value;

    #[test]
    fn check_empty() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![]);

        assert!(res.is_ok());
        assert_eq!(res.unwrap().iter().len(), 0)
    }

    #[test]
    fn check_declaration() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Declare {
            name: "x".to_string(),
            value: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstBool as u8, 0]
        )
    }

    #[test]
    fn check_inline_value() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::Int(0))]);

        assert!(res.is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstInt as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]));
    }

    #[test]
    fn check_string_value() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::String("parts".to_string()))]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstString as u8, 0]
        );
        assert_eq!(c.constant_pool[0], Value::String("parts".to_string()));
    }

    #[test]
    fn check_duplicate_string_value() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![
            Ast::Value(ParserValue::String("parts".to_string())),
            Ast::Value(ParserValue::String("parts".to_string())),
        ]);

        assert!(res.is_ok());
        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstString as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstString as u8,
                0
            ]
        );
        assert_eq!(c.constant_pool[0], Value::String("parts".to_string()));
    }

    #[test]
    fn check_multi_string_value() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![
            Ast::Value(ParserValue::String("parts".to_string())),
            Ast::Value(ParserValue::String("rust".to_string())),
            Ast::Value(ParserValue::String("parts".to_string())),
        ]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstString as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstString as u8,
                1,
                OpCode::Load as u8,
                2,
                OpCode::ConstString as u8,
                0
            ]
        );
        assert_eq!(c.constant_pool[0], Value::String("parts".to_string()));
        assert_eq!(c.constant_pool[1], Value::String("rust".to_string()));
    }

    #[test]
    fn check_ref() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![
            Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            },
            Ast::Declare {
                name: "y".to_string(),
                value: Box::new(Ast::Value(ParserValue::Ref("x".to_string()))),
            },
        ]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstReg as u8,
                0,
            ]
        )
    }

    #[test]
    fn check_fun_no_args() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::Fun {
            args: vec![],
            body: Box::new(Ast::Return {
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            }),
        })]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstFun as u8, 0]
        );

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 0,
                body: vec![
                    OpCode::Load as u8,
                    0,
                    OpCode::ConstBool as u8,
                    0,
                    OpCode::Return as u8,
                    0
                ]
            }
        )
    }

    #[test]
    fn check_fun_one_arg() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::Fun {
            args: vec!["n".to_string()],
            body: Box::new(Ast::Return {
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            }),
        })]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstFun as u8, 0]
        );

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 1,
                body: vec![
                    OpCode::Load as u8,
                    1,
                    OpCode::ConstBool as u8,
                    0,
                    OpCode::Return as u8,
                    1
                ]
            }
        )
    }

    #[test]
    fn check_fun_multiple_args() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::Fun {
            args: vec!["n".to_string(), "i".to_string()],
            body: Box::new(Ast::Return {
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            }),
        })]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstFun as u8, 0]
        );

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 2,
                body: vec![
                    OpCode::Load as u8,
                    2,
                    OpCode::ConstBool as u8,
                    0,
                    OpCode::Return as u8,
                    2
                ]
            }
        )
    }

    #[test]
    fn check_return() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Return {
            value: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Return as u8,
                0
            ]
        );
    }

    #[test]
    fn check_raise() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Return {
            value: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Return as u8,
                0
            ]
        );
    }

    #[test]
    fn check_call() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Call {
            what: Box::new(Ast::Value(ParserValue::String("fib".to_string()))),
            args: vec![Ast::Value(ParserValue::Int(0))],
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstString as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstInt as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                OpCode::Call as u8,
                2,
                0,
                1,
                1,
            ]
        );
    }

    #[test]
    fn check_binary() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Binary {
            left: Box::new(Ast::Value(ParserValue::Bool(false))),
            right: Box::new(Ast::Value(ParserValue::Bool(false))),
            operator: BinaryOperator::Add,
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                0,
                OpCode::Binary as u8,
                0,
                2,
                0,
                1
            ]
        );
    }

    #[test]
    fn check_if() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::If {
            then_branch: Box::new(Ast::Value(ParserValue::Bool(true))),
            else_branch: Some(Box::new(Ast::Value(ParserValue::Bool(false)))),
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                7,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                1,
                OpCode::JumpBy as u8,
                4,
                0,
                OpCode::Load as u8,
                2,
                OpCode::ConstBool as u8,
                0,
            ]
        )
    }

    #[test]
    fn check_if_no_else() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::If {
            then_branch: Box::new(Ast::Value(ParserValue::Bool(true))),
            else_branch: None,
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                4,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                1
            ]
        )
    }

    #[test]
    fn check_continue() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::For {
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
            body: (Box::new(Ast::ContinueCode)),
        }]);

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                6,
                0,
                OpCode::JumpBack as u8,
                11,
                0,
                OpCode::JumpBack as u8,
                14,
                0
            ]));
    }
    #[test]

    fn check_break() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::For {
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
            body: (Box::new(Ast::BreakCode)),
        }]);

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                6,
                0,
                OpCode::Jump as u8,
                14,
                0,
                OpCode::JumpBack as u8,
                14,
                0
            ]));
    }

    #[test]
    fn check_obj_no_entries() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::Object(vec![]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        assert!(
            c.constant_pool
                .get(0)
                .is_some_and(|x| if let Value::Object(entries) = x {
                    entries.borrow().len() == 0
                } else {
                    false
                })
        )
    }

    #[test]
    fn check_obj_with_entries() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::Object(vec![(
            ParserValue::Int(100),
            ParserValue::Bool(false),
        )]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        let obj = c.constant_pool.get(0).expect("Expected actual value");

        let mut expected = HashMap::new();

        expected.insert(Value::Int(100).get_hash(), Value::Bool(false));

        assert_eq!(*obj, Value::Object(Rc::new(RefCell::new(expected))));
    }

    #[test]
    fn check_arr_no_entries() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::List(vec![]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        assert!(
            c.constant_pool
                .get(0)
                .is_some_and(|x| if let Value::Object(entries) = x {
                    entries.borrow().len() == 0
                } else {
                    false
                })
        )
    }

    #[test]
    fn check_arr_with_entries() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Value(ParserValue::List(vec![
            ParserValue::Int(100),
            ParserValue::Bool(false),
        ]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        let obj = c.constant_pool.get(0).expect("Expected valid value");

        let mut expected = HashMap::new();

        expected.insert(Value::Int(0).get_hash(), Value::Int(100));
        expected.insert(Value::Int(1).get_hash(), Value::Bool(false));

        assert_eq!(*obj, Value::Object(Rc::new(RefCell::new(expected))));
    }

    #[test]
    fn check_assign_no_declaration() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![Ast::Set {
            name: Box::from(Ast::Value(ParserValue::Ref("x".to_string()))),
            value: Box::from(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstBool as u8, 0])
        );
    }

    #[test]
    fn check_assign_with_declaration() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![
            Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(ParserValue::Bool(true))),
            },
            Ast::Set {
                name: Box::from(Ast::Value(ParserValue::Ref("x".to_string()))),
                value: Box::from(Ast::Value(ParserValue::Bool(false))),
            },
        ]);

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                1,
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0
            ]));
    }

    #[test]
    fn check_assign_with_dot() {
        let mut c = Compiler::new("./".into());

        let res = c.compile_all(vec![
            Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(ParserValue::Object(vec![]))),
            },
            Ast::Set {
                name: Box::from(Ast::Dot {
                    accessor: Box::new(Ast::Value(ParserValue::Ref("x".to_string()))),
                    access: Box::new(Ast::Value(ParserValue::Ref("y".to_string()))),
                }),
                value: Box::from(Ast::Value(ParserValue::Bool(false))),
            },
        ]);

        let hash = Value::Ref("y".to_string()).get_hash();

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstObj as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                0,
                OpCode::SetProperty as u8,
                0, //Register
                1, //Const
                1  //Value register
            ]));

        assert_eq!(c.constant_pool[1], Value::Hash(hash.try_into().unwrap()))
    }
}
