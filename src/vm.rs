use crate::std::StdModule;
use crate::value::{NativeFunction, Value};
use std::collections::HashMap;

use crate::compiler::OpCode;

#[derive(Clone)]
pub struct Frame {
    pub registers: [Value; 256],
    pub ip: usize,
    pub bytecode: Vec<u8>,
    pub return_reg: u8,
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
    pub constants: Vec<Value>,
    exit_value: Option<Value>,
    pub patch_table: HashMap<u64, HashMap<u64, Value>>,
    pub native_functions: Vec<NativeFunction>,
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
            patch_table: HashMap::new(),
            native_functions: StdModule::get_core().functions,
        }
    }

    pub fn with_natives(
        code: Vec<u8>,
        constants: Vec<Value>,
        natives: Vec<NativeFunction>,
    ) -> Self {
        let mut vm = Self::new(code, constants);
        vm.native_functions.extend(natives);
        vm
    }

    pub fn run_with_frame(&mut self, frame: Frame) -> Result<Option<Value>, Error> {
        self.frames = vec![frame];
        self.run()
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
                if current_frame.ip >= current_frame.bytecode.len() {
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
                        | OpCode::ConstObj
                        | OpCode::ConstAst
                        | OpCode::ConstParserValue => {
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
                        self.frames.pop();
                        break;
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

                            let result = (native_fn.call)(args).map_err(|e| {
                                panic!("Error in native function: {:?}", e);
                            })?;

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
                        let val = obj_ref.borrow().get(&hash).cloned();

                        if let Some(v) = val {
                            self.current()?.registers[dest] = v;
                        } else if let Some(patched) =
                            self.patch_table.get(&0).and_then(|p| p.get(&hash))
                        {
                            self.current()?.registers[dest] = patched.clone();
                        } else {
                            return Err(Error::UnexpectedType);
                        }
                    } else {
                        return Err(Error::UnexpectedType);
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
                        self.native_functions
                            .iter()
                            .find(|f| {
                                Value::Hash(Value::String(f.name.to_string()).get_hash()) == hash
                            })
                            .unwrap()
                            .clone(),
                    );
                }
                OpCode::ConstAst | OpCode::ConstParserValue => return Err(Error::UnexpectedType),
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