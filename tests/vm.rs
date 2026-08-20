#[cfg(test)]
mod tests {
    use parts::emitter::OpCode;
    use parts::value::Value;
    use parts::vm::VM;

    #[test]
    fn check_double_return() {
        let code = [OpCode::Return as u8, 0, OpCode::Return as u8, 0];

        let mut vm = VM::new(code.to_vec(), vec![]);

        let res = vm.run();

        assert!(res.is_ok_and(|val| val == Some(Value::Int(0))))
    }

    #[test]
    fn check_call_no_args() {
        //[load @ 0 cosnt @ 0], [Call, return @ 1, func @ 0, 0 args], [return @ 1]
        let code = vec![
            OpCode::Load as u8,
            0,
            OpCode::ConstFun as u8,
            0,
            OpCode::Call as u8,
            1,
            0,
            0,
            OpCode::Return as u8,
            1,
        ];

        let constants = vec![Value::Fun {
            arity: 0,
            body: vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                1,
                OpCode::Return as u8,
                0,
            ],
        }];

        let mut vm = VM::new(code, constants);

        let res = vm.run();

        assert!(res.is_ok_and(|val| val.is_some_and(|deep| deep == Value::Bool(true))))
    }

    #[test]
    fn check_call_one_arg() {
        //[load @ 0 cosnt @ 0], [Call, return @ 1, func @ 0, 1 arg], [return @ 1]
        let code = vec![
            OpCode::Load as u8,
            0,
            OpCode::ConstFun as u8,
            0,
            OpCode::Load as u8,
            1,
            OpCode::ConstBool as u8,
            0,
            OpCode::Call as u8,
            2,
            0,
            1,
            1,
            OpCode::Return as u8,
            2,
        ];

        let constants = vec![Value::Fun {
            arity: 0,
            body: vec![OpCode::Return as u8, 0],
        }];

        let mut vm = VM::new(code, constants);

        let res = vm.run();

        assert!(res.is_ok_and(|val| val.is_some_and(|deep| deep == Value::Bool(false))))
    }

    #[test]
    fn check_test_binary() {
        let code = vec![
            OpCode::Load as u8,
            0,
            OpCode::ConstInt as u8,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            OpCode::Load as u8,
            1,
            OpCode::ConstInt as u8,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            OpCode::Binary as u8,
            0,
            2,
            0,
            1,
            OpCode::Return as u8,
            2,
        ];

        let constants = vec![];

        let mut vm = VM::new(code, constants);

        assert!(
            vm.run()
                .is_ok_and(|val| val.is_some_and(|deep| deep == Value::Int(2)))
        )
    }
    #[test]
    fn check_enum_in_function_frame_and_return() {
        use std::rc::Rc;
        let power_hash = Value::String(Rc::new("power".to_string())).get_hash();

        // Function body (runs at fp = 256):
        // Load reg 0 with Double 42.0
        // Load reg 1 with ConstEnum(enum 0, tag 0, 1 field: power_hash from reg 0)
        // Return reg 1
        let mut func_body = vec![
            OpCode::Load as u8,
            0,
            OpCode::ConstDouble as u8,
        ];
        func_body.extend(42.0f64.to_le_bytes());
        func_body.extend(vec![
            OpCode::Load as u8,
            1,
            OpCode::ConstEnum as u8,
            0, // enum_idx
            0, // tag
            1, // count
        ]);
        func_body.extend(power_hash.to_le_bytes());
        func_body.push(0); // reg 0 in callee frame
        func_body.extend(vec![
            OpCode::Return as u8,
            1,
        ]);

        // Main code (runs at fp = 0):
        // Load reg 0 with func (constant 0)
        // Call reg 0 with 0 args, return into reg 1
        // GetProperty reg 2 from obj reg 1, key const 1 (hash)
        // Return reg 2
        let main_code = vec![
            OpCode::Load as u8,
            0,
            OpCode::ConstFun as u8,
            0,
            OpCode::Call as u8,
            1, // return into reg 1
            0, // func is at reg 0
            0, // 0 args
            OpCode::GetProperty as u8,
            2, // dest reg 2
            1, // obj reg 1
            1, // const idx 1 (hash)
            OpCode::Return as u8,
            2,
        ];

        let constants = vec![
            Value::Fun {
                arity: 0,
                body: func_body,
            },
            Value::Hash(power_hash),
        ];

        let mut vm = VM::new(main_code, constants);
        let res = vm.run();
        assert_eq!(res, Ok(Some(Value::Double(42.0))));
    }
}
