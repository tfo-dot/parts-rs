use crate::compiler::{OpCode, Value};

struct Frame {
    registers: [Value; 256],
    ip: usize,
    bytecode: Vec<u8>,
    return_reg: u8,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    FrameUnderflow,
    UnexpectedType,
}

pub struct VM {
    frames: Vec<Frame>,
    constants: Vec<Value>,
    exit_value: Option<Value>,
}

impl VM {
    pub fn new(code: Vec<u8>, constants: Vec<Value>) -> Self {
        Self {
            frames: vec![Frame {
                registers: [const { Value::Int(0) }; 256],
                ip: 0,
                bytecode: code,
                return_reg: 0,
            }],
            constants,
            exit_value: None,
        }
    }

    fn current(&mut self) -> Result<&mut Frame, Error> {
        self.frames.last_mut().ok_or(Error::FrameUnderflow)
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        let frame = self.current()?;
        let b = frame.bytecode[frame.ip];
        frame.ip += 1;
        Ok(b)
    }

    fn read_n(&mut self, n: usize) -> Result<&[u8], Error> {
        let frame = self.current()?;
        let slice = &frame.bytecode[frame.ip..frame.ip + n];
        frame.ip += n;
        Ok(slice)
    }

    pub fn run(&mut self) -> Result<Option<Value>, Error> {
        loop {
            //welp, if it's true the we're poping more frames than we push
            if self.frames.is_empty() {
                break;
            }

            if let Some(current_frame) = self.frames.last() {
                if current_frame.ip + 1 > current_frame.bytecode.len() {
                    break;
                }
            }

            let opcode = self.read_byte()?;

            match OpCode::try_from(opcode).unwrap() {
                OpCode::Load => {
                    let dest = self.read_byte()? as usize;

                    let value_type = OpCode::try_from(self.read_byte()?).unwrap();

                    match value_type {
                        OpCode::ConstInt => {
                            let raw_bytes: [u8; 8] = self.read_n(8)?.try_into().unwrap();

                            self.current()?.registers[dest] =
                                Value::Int(i64::from_le_bytes(raw_bytes));
                        }
                        OpCode::ConstDouble => {
                            let raw_bytes: [u8; 8] = self.read_n(8)?.try_into().unwrap();

                            self.current()?.registers[dest] =
                                Value::Double(f64::from_le_bytes(raw_bytes));
                        }
                        OpCode::ConstBool => {
                            self.current()?.registers[dest] = Value::Bool(self.read_byte()? != 0);
                        }
                        OpCode::ConstString
                        | OpCode::ConstRef
                        | OpCode::ConstFun
                        | OpCode::ConstObj => {
                            let byte = self.read_byte()? as usize;
                            self.current()?.registers[dest] = self.constants[byte].clone();
                        }
                        _ => return Err(Error::UnexpectedType),
                    }
                }
                OpCode::Return => {
                    let src_reg = self.read_byte()? as usize;

                    let return_value = self.current()?.registers[src_reg].clone();

                    if self.frames.len() <= 1 {
                        self.exit_value = Some(return_value.clone());
                        continue;
                    }

                    let frame = self.frames.pop().ok_or(Error::FrameUnderflow)?;

                    if let Some(caller_frame) = self.frames.last_mut() {
                        caller_frame.registers[frame.return_reg as usize] = return_value;
                    }
                }
                OpCode::ConstInt
                | OpCode::ConstDouble
                | OpCode::ConstBool
                | OpCode::ConstString
                | OpCode::ConstRef
                | OpCode::ConstFun
                | OpCode::ConstObj => return Err(Error::UnexpectedType),
                OpCode::Call => {
                    let dest_reg = self.read_byte()?;
                    let fun_reg = self.read_byte()?;

                    let arg_count = self.read_byte()?;

                    let func_val = self.current()?.registers[fun_reg as usize].clone();

                    if let Value::Fun { arity: _, body } = func_val {
                        let mut new_frame = Frame {
                            registers: [const { Value::Int(0) }; 256],
                            ip: 0,
                            bytecode: body,
                            return_reg: dest_reg,
                        };

                        for i in 0..arg_count {
                            let idx = self.read_byte()? as usize;
                            new_frame.registers[i as usize] =
                                self.current()?.registers[idx].clone();
                        }

                        self.frames.push(new_frame);
                    } else {
                        return Err(Error::UnexpectedType);
                    }
                }
                OpCode::Jump => {
                    let offset = self.read_n(2)?.try_into().unwrap();
                    self.current()?.ip = u16::from_le_bytes(offset) as usize;
                }
                OpCode::JumpIf => {
                    let jump_condition = self.read_byte()? as usize;

                    let cond_value = self.current()?.registers[jump_condition].clone();

                    if Self::is_truthy(cond_value) {
                        let offset = self.read_n(2)?.try_into().unwrap();
                        self.current()?.ip += u16::from_le_bytes(offset) as usize;
                    }
                }
                OpCode::JumpNot => {
                    let jump_condition = self.read_byte()? as usize;

                    let cond_value = self.current()?.registers[jump_condition].clone();

                    if !Self::is_truthy(cond_value) {
                        let offset = self.read_n(2)?.try_into().unwrap();
                        self.current()?.ip += u16::from_le_bytes(offset) as usize;
                    }
                }
                OpCode::JumpBack => {
                    let offset = self.read_n(2)?.try_into().unwrap();
                    self.current()?.ip -= u16::from_le_bytes(offset) as usize;
                }
                OpCode::Binary => {
                    let op = self.read_byte()? as usize;

                    let dest = self.read_byte()? as usize;

                    let left_reg = self.read_byte()? as usize;
                    let right_reg = self.read_byte()? as usize;

                    let current_frame = self.current().unwrap();

                    let left = current_frame.registers[left_reg].clone();
                    let right = current_frame.registers[right_reg].clone();

                    let res = Self::binary(op, left, right);

                    current_frame.registers[dest] = res
                }
                _ => todo!(),
            }
        }

        Ok(self.exit_value.clone())
    }

    pub fn is_truthy(val: Value) -> bool {
        match val {
            Value::Int(raw) => raw.abs() > 0,
            Value::Double(raw) => raw.abs() > 0.0,
            Value::Bool(raw) => raw,
            Value::String(raw) => raw.len() > 0,
            //TODO check if it's true XD
            Value::Ref(_) | Value::Hash(_) => unreachable!(),
            Value::Fun { arity: _, body: _ } => true,
            Value::Object(items) => items.len() > 0,
        }
    }

    pub fn binary(op_type: usize, left: Value, right: Value) -> Value {
        match op_type {
            0 => (left + right).expect("Unexpected error"),
            1 => (left - right).expect("Unexpected error"),
            2 => (left * right).expect("Unexpected error"),
            3 => (left / right).expect("Unexpected error"),
            4 => Value::Bool(left == right),
            5 => Value::Bool(left > right),
            6 => Value::Bool(left < right),
            7 => (left % right).expect("Unexpected error"),

            _ => panic!("UnexpectedType"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VM;
    use crate::compiler::{OpCode, Value};

    #[test]
    fn check_inline_const_load() {
        let code = [
            OpCode::Load as u8,
            0,
            OpCode::ConstInt as u8,
            //100 as i64 le byte
            100,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];

        let mut vm = VM::new(code.to_vec(), vec![]);

        let res = vm.run();

        assert!(res.is_ok_and(|val| val.is_none()));
        assert_eq!(code.len(), vm.frames.last().unwrap().ip);
        assert_eq!(vm.frames.last().unwrap().registers[0], Value::Int(100))
    }

    #[test]
    fn check_scope_const_load() {
        let code = [OpCode::Load as u8, 0, OpCode::ConstString as u8, 0];

        let mut vm = VM::new(code.to_vec(), vec![Value::String("Hello".to_string())]);

        let res = vm.run();

        assert!(res.is_ok_and(|val| val.is_none()));
        assert_eq!(code.len(), vm.frames.last().unwrap().ip);
        assert_eq!(
            vm.frames.last().unwrap().registers[0],
            Value::String("Hello".to_string())
        )
    }

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
