#[cfg(test)]
mod tests {
    use parts::compiler::OpCode;
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
}
