use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::compiler::{NativeFunction, OpCode, Value};

#[derive(Clone)]
pub struct StdModule {
    pub functions: Vec<NativeFunction>,
}

impl StdModule {
    pub fn get_core() -> Self {
        Self {
            functions: vec![
                NativeFunction {
                    name: "println",
                    arity: 1,
                    call: |args| {
                        for arg in args {
                            print!("{}", arg)
                        }
                        println!();

                        Ok(Value::Bool(true))
                    },
                },
                NativeFunction {
                    name: "timestamp",
                    arity: 0,
                    call: |_| {
                        let ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_micros();

                        Ok(Value::Int(ts as i64))
                    },
                },
                NativeFunction {
                    name: "iter_of",
                    arity: 1,
                    call: |args| {
                        return match &args[0] {
                            Value::String(_) => todo!(),
                            Value::Object(map) => {
                                let mut hash_map = HashMap::new();

                                hash_map.insert(
                                    Value::String("data".to_string()).get_hash(),
                                    Value::Object(map.clone()),
                                );

                                hash_map.insert(
                                    Value::String("index".to_string()).get_hash(),
                                    Value::Int(0),
                                );

                                Ok(Value::Object(Rc::new(RefCell::new(hash_map))))
                            }
                            _ => Err("UnexpectedType, only object/strings".to_string()),
                        };
                    },
                },
                NativeFunction {
                    name: "get_next",
                    arity: 1,
                    call: |args| {
                        if let Value::Object(obj_ref) = &args[0] {
                            let mut map = obj_ref.borrow_mut(); // Gain mutable access to the original object

                            let data_hash = Value::String("data".to_string()).get_hash();
                            let index_hash = Value::String("index".to_string()).get_hash();

                            let data = map.get(&data_hash).cloned().ok_or("Missing data")?;
                            let index = if let Some(Value::Int(i)) = map.get(&index_hash) {
                                *i
                            } else {
                                0
                            };

                            if let Value::Object(items_ref) = data {
                                let items = items_ref.borrow();

                                let entry_hash = items.keys().nth(index as usize);

                                if entry_hash.is_none() {
                                    return Ok(Value::Bool(false));
                                }

                                if let Some(val) = items.get(&entry_hash.unwrap()) {
                                    map.insert(index_hash, Value::Int(index + 1));

                                    return Ok(val.clone());
                                }
                            }

                            Ok(Value::Bool(false))
                        } else {
                            Err("UnexpectedType, expected object".to_string())
                        }
                    },
                },
                NativeFunction {
                    name: "has_next",
                    arity: 1,
                    call: |args| {
                        if let Value::Object(obj_ref) = &args[0] {
                            let map = obj_ref.borrow();

                            let data_hash = Value::String("data".to_string()).get_hash();
                            let index_hash = Value::String("index".to_string()).get_hash();

                            let data = map.get(&data_hash).cloned().ok_or("Missing data")?;
                            let index = if let Some(Value::Int(i)) = map.get(&index_hash) {
                                *i
                            } else {
                                0
                            };

                            if let Value::Object(items_ref) = data {
                                let items = items_ref.borrow();

                                let entry_hash = items.keys().nth(index as usize);

                                if entry_hash.is_none() {
                                    return Ok(Value::Bool(false));
                                }

                                return Ok(Value::Bool(items.get(&entry_hash.unwrap()).is_some()));
                            }

                            Ok(Value::Bool(false))
                        } else {
                            Err("UnexpectedType, expected object".to_string())
                        }
                    },
                },
            ],
        }
    }
}

#[derive(Clone)]
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
    UnexpectedTypeLoad(OpCode),
    UnexpectedTypeCall,
    UnexpectedType,
}

#[derive(Clone)]
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
                        OpCode::ConstReg => {
                            let byte = self.read_byte()? as usize;
                            self.current()?.registers[dest] =
                                self.current()?.registers[byte].clone();
                        }
                        _ => return Err(Error::UnexpectedTypeLoad(value_type)),
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
                | OpCode::ConstObj
                | OpCode::ConstReg => return Err(Error::UnexpectedType),
                OpCode::Call => {
                    let dest_reg = self.read_byte()?;
                    let fun_reg = self.read_byte()?;

                    let arg_count = self.read_byte()?;

                    let func_val = self.current()?.registers[fun_reg as usize].clone();

                    match func_val {
                        Value::Fun { arity: _, body } => {
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
                        }
                        Value::NativeFun(native_fn) => {
                            let mut args = Vec::new();
                            for _ in 0..arg_count {
                                let arg_reg = self.read_byte()? as usize;

                                let arg = self.current()?.registers[arg_reg].clone();

                                args.push(arg);
                            }

                            // Execute the Rust function
                            let result = (native_fn.call)(args).map_err(|e| {
                                panic!("Error in native function: {:?}", e);
                            })?;

                            // Store result in the destination register
                            self.current()?.registers[dest_reg as usize] = result;
                        }
                        _ => {
                            return Err(Error::UnexpectedTypeCall);
                        }
                    }
                }
                OpCode::Jump => {
                    let offset = self.read_n(2)?.try_into().unwrap();
                    self.current()?.ip = u16::from_le_bytes(offset) as usize;
                }
                OpCode::JumpBy => {
                    let offset = self.read_n(2)?.try_into().unwrap();
                    self.current()?.ip += u16::from_le_bytes(offset) as usize;
                }
                OpCode::JumpIf => {
                    let jump_condition = self.read_byte()? as usize;

                    let cond_value = self.current()?.registers[jump_condition].clone();
                    let offset = self.read_n(2)?.try_into().unwrap();

                    if Self::is_truthy(cond_value) {
                        self.current()?.ip += u16::from_le_bytes(offset) as usize;
                    }
                }
                OpCode::JumpNot => {
                    let jump_condition = self.read_byte()? as usize;

                    let cond_value = self.current()?.registers[jump_condition].clone();

                    let offset = self.read_n(2)?.try_into().unwrap();

                    if !Self::is_truthy(cond_value) {
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

                    current_frame.registers[dest] = Self::binary(op, left, right);
                }
                OpCode::GetProperty => {
                    let dest = self.read_byte()? as usize;

                    let src_idx = self.read_byte()? as usize;

                    let idx = self.read_byte()? as usize;

                    let hash = match self.constants.get(idx) {
                        Some(Value::Hash(h)) => *h,
                        _ => panic!("Expected hash constant at index {}", idx),
                    };

                    if let Value::Object(obj_ref) = &self.current()?.registers[src_idx] {
                        // Use .borrow() to read
                        let value = obj_ref
                            .borrow()
                            .get(&hash)
                            .cloned()
                            .expect("No object found");
                        self.current()?.registers[dest] = value;
                    }
                }
                OpCode::SetProperty => {
                    let obj_idx = self.read_byte()? as usize;
                    let const_idx = self.read_byte()? as usize;
                    let val_idx = self.read_byte()? as usize;

                    let hash = match self.constants.get(const_idx) {
                        Some(Value::Hash(h)) => *h,
                        _ => panic!("Expected hash constant"),
                    };

                    let new_val = self.current()?.registers[val_idx].clone();

                    if let Value::Object(obj_ref) = &self.current()?.registers[obj_idx] {
                        // Use .borrow_mut() to modify the shared map in place!
                        obj_ref.borrow_mut().insert(hash, new_val);
                    }
                }
                OpCode::LoadNative => {
                    let dest = self.read_byte()? as usize;
                    let hash_idx = self.read_byte()? as usize;

                    let hash = match self.constants.get(hash_idx) {
                        Some(Value::Hash(h)) => Value::Hash(*h),
                        _ => panic!("Expected hash constant"),
                    };

                    self.current()?.registers[dest] = Value::NativeFun(
                        StdModule::get_core()
                            .functions
                            .iter()
                            .find(|f| {
                                Value::Hash(Value::String(f.name.to_string()).get_hash()) == hash
                            })
                            .unwrap()
                            .clone(),
                    );
                }
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
            Value::Fun { .. } => true,
            Value::NativeFun(_) => true,
            Value::Object(items) => items.borrow().len() > 0,
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

            _ => panic!("UnexpectedType bin"),
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
