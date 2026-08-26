use crate::emitter::OpCode;
use crate::std::StdModule;
use crate::value::{NativeFunction, Value};
use rustc_hash::FxHashMap;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
pub struct Frame {
    pub pointer: usize,
    pub ip: usize,
    pub bytecode: Rc<Vec<u8>>,
    pub return_reg: u8,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    FrameUnderflow,
    UnexpectedTypeLoad(OpCode),
    UnexpectedTypeCall,
    UnexpectedType,
    PropertyNotFound(u64),
    NativeFunctionFailed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FrameUnderflow => write!(f, "call stack underflow"),
            Error::UnexpectedTypeLoad(op) => write!(f, "unexpected value type for load operation ({:?})", op),
            Error::UnexpectedTypeCall => write!(f, "attempted to call a non-callable value"),
            Error::UnexpectedType => write!(f, "unexpected value type for operation"),
            Error::PropertyNotFound(hash) => write!(f, "property with hash {:#018x} not found", hash),
            Error::NativeFunctionFailed(msg) => write!(f, "native function failed: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn to_diagnostic(&self, file: Option<&str>) -> crate::diagnostic::Diagnostic {
        let mut diag = crate::diagnostic::Diagnostic::error(format!("runtime error: {}", self));
        if let Some(f) = file {
            diag = diag.with_file(f);
        }
        diag
    }
}

#[derive(Clone)]
pub struct VM {
    pub stack: Vec<Value>,
    pub frames: Vec<Frame>,
    pub constants: Vec<Value>,
    exit_value: Option<Value>,
    pub patch_table: FxHashMap<u64, FxHashMap<u64, Value>>,
    pub native_functions: Vec<NativeFunction>,
}

impl VM {
    pub fn new(code: Vec<u8>, constants: Vec<Value>) -> Self {
        let mut stack = Vec::with_capacity(8192);

        stack.resize(256, Value::Int(0));

        Self {
            frames: vec![Frame {
                pointer: 0,
                ip: 0,
                bytecode: Rc::new(code),
                return_reg: 0,
            }],
            stack,
            constants,
            exit_value: None,
            patch_table: FxHashMap::default(),
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
        let mut fp = self.frames.last().unwrap().pointer;

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

                            self.stack[fp + dest] = Value::Int(i64::from_le_bytes(raw_bytes));
                        }
                        OpCode::ConstDouble => {
                            let raw_bytes: [u8; 8] = self.read_n(8)?.try_into().unwrap();

                            self.stack[fp + dest] = Value::Double(f64::from_le_bytes(raw_bytes));
                        }
                        OpCode::ConstBool => {
                            self.stack[fp + dest] = Value::Bool(self.read_byte()? != 0);
                        }
                        OpCode::ConstString | OpCode::ConstRef | OpCode::ConstFun => {
                            let bytes: [u8; 2] = self.read_n(2)?.try_into().unwrap();
                            let idx = u16::from_le_bytes(bytes) as usize;
                            self.stack[fp + dest] = self.constants[idx].clone();
                        }
                        OpCode::ConstObj => {
                            let bytes: [u8; 2] = self.read_n(2)?.try_into().unwrap();
                            let idx = u16::from_le_bytes(bytes) as usize;
                            if let Some(Value::Object(ref_cell)) = self.constants.get(idx) {
                                let cloned_map = ref_cell.borrow().clone();
                                self.stack[fp + dest] =
                                    Value::Object(Rc::new(RefCell::new(cloned_map)));
                            } else {
                                self.stack[fp + dest] =
                                    Value::Object(Rc::new(RefCell::new(FxHashMap::default())));
                            }
                        }
                        OpCode::ConstReg => {
                            let byte = self.read_byte()? as usize;
                            self.stack[fp + dest] = self.stack[fp + byte].clone();
                        }
                        OpCode::ConstEnum => {
                            let bytes: [u8; 2] = self.read_n(2)?.try_into().unwrap();
                            let enum_idx = u16::from_le_bytes(bytes);
                            let tag = self.read_byte()?;
                            let count = self.read_byte()?;

                            let mut args = Vec::with_capacity(count as usize);
                            for _ in 0..count {
                                let raw_key_bytes: [u8; 8] = self.read_n(8)?.try_into().unwrap();
                                let hash = u64::from_le_bytes(raw_key_bytes);

                                let arg_reg = self.read_byte()? as usize;
                                let arg_val = self.stack[fp + arg_reg].clone();
                                args.push((hash, arg_val));
                            }

                            self.stack[fp + dest] = Value::EnumField {
                                const_idx: enum_idx as usize,
                                tag,
                                args,
                            };
                        }
                        _ => return Err(Error::UnexpectedTypeLoad(value_type)),
                    }
                }
                OpCode::Return => {
                    let src_reg = self.read_byte()? as usize;
                    let current_fp = self.current()?.pointer;

                    let return_value = self.stack[current_fp + src_reg].clone();

                    if self.frames.len() <= 1 {
                        self.exit_value = Some(return_value);
                        self.frames.pop();
                        break;
                    }

                    let frame = self.frames.pop().unwrap();

                    self.stack.truncate(frame.pointer);

                    let caller_fp = self.current()?.pointer;
                    self.stack[caller_fp + frame.return_reg as usize] = return_value;
                    fp = self.frames.last().unwrap().pointer;
                }
                OpCode::ConstInt
                | OpCode::ConstDouble
                | OpCode::ConstBool
                | OpCode::ConstString
                | OpCode::ConstRef
                | OpCode::ConstFun
                | OpCode::ConstObj
                | OpCode::ConstEnum
                | OpCode::ConstReg => return Err(Error::UnexpectedType),
                OpCode::Call => {
                    let dest_reg = self.read_byte()?;
                    let fun_reg = self.read_byte()?;
                    let arg_count = self.read_byte()?;

                    let func_val = self.stack[fp + fun_reg as usize].clone();
                    match func_val {
                        Value::Fun { arity: _, body } => {
                            let new_fp = self.stack.len();

                            for _ in 0..arg_count {
                                let arg_reg_idx = self.read_byte()? as usize;
                                let arg_val = self.stack[fp + arg_reg_idx].clone();
                                self.stack.push(arg_val);
                            }

                            let padding = 256 - arg_count as usize;
                            self.stack.resize(self.stack.len() + padding, Value::Int(0));

                            self.frames.push(Frame {
                                ip: 0,
                                pointer: new_fp,
                                return_reg: dest_reg,
                                bytecode: Rc::new(body),
                            });
                            fp = new_fp;
                        }
                        Value::NativeFun(native_fn) => {
                            let mut args = Vec::new();
                            let current_fp = self.current()?.pointer;

                            for _ in 0..arg_count {
                                let arg_reg = self.read_byte()? as usize;
                                let arg = self.stack[current_fp + arg_reg].clone();
                                args.push(arg);
                            }

                            let current_ip = self.current()?.ip;

                            let result = (native_fn.call)(args).map_err(|e| {
                                Error::NativeFunctionFailed(format!(
                                    "Error in native function '{}': {}, IP: {}",
                                    native_fn.name, e, current_ip
                                ))
                            })?;

                            self.stack[fp + dest_reg as usize] = result;
                        }
                        _ => {
                            let frame_pointer = self.current()?.pointer;
                            eprintln!(
                                "UnexpectedTypeCall in func: dest_reg = {}, fun_reg = {}, func_val = {:?}, fp = {}, stack_slice = {:?}",
                                dest_reg,
                                fun_reg,
                                func_val,
                                frame_pointer,
                                &self.stack[frame_pointer
                                    ..std::cmp::min(self.stack.len(), frame_pointer + 20)]
                            );
                            return Err(Error::UnexpectedTypeCall);
                        }
                    }
                }
                OpCode::Jump => {
                    let offset = self.read_n(2)?.try_into().unwrap();
                    self.current()?.ip = u16::from_le_bytes(offset) as usize;
                }
                OpCode::JumpNot => {
                    let jump_condition = self.read_byte()? as usize;

                    let cond_value = self.stack[fp + jump_condition].clone();

                    let offset = self.read_n(2)?.try_into().unwrap();

                    if !Self::is_truthy(cond_value) {
                        self.current()?.ip = u16::from_le_bytes(offset) as usize;
                    }
                }
                OpCode::Binary => {
                    let op = self.read_byte()? as usize;

                    let dest = self.read_byte()? as usize;

                    let left_reg = self.read_byte()? as usize;
                    let right_reg = self.read_byte()? as usize;

                    let left = self.stack[fp + left_reg].clone();
                    let right = self.stack[fp + right_reg].clone();

                    self.stack[fp + dest] = Self::binary(op, left, right);
                }
                OpCode::GetProperty => {
                    let dest = self.read_byte()? as usize;
                    let src_idx = self.read_byte()? as usize;
                    let bytes: [u8; 2] = self.read_n(2)?.try_into().unwrap();
                    let idx = u16::from_le_bytes(bytes) as usize;

                    let hash = match self.constants.get(idx) {
                        Some(Value::Hash(h)) => *h,
                        _ => panic!("Expected hash constant at index {}", idx),
                    };
                    if let Value::Object(obj_ref) = &self.stack[fp + src_idx] {
                        let val = obj_ref.borrow().get(&hash).cloned();

                        if let Some(v) = val {
                            self.stack[fp + dest] = v;
                        } else if let Some(patched) =
                            self.patch_table.get(&0).and_then(|p| p.get(&hash))
                        {
                            self.stack[fp + dest] = patched.clone();
                        } else {
                            return Err(Error::PropertyNotFound(hash));
                        }
                    } else if let Value::EnumField {
                        const_idx: _,
                        tag: _,
                        args,
                    } = &self.stack[fp + src_idx]
                    {
                        if let Some((_, val)) = args.iter().find(|(h, _)| *h == hash) {
                            self.stack[fp + dest] = val.clone();
                        } else {
                            return Err(Error::PropertyNotFound(hash));
                        }
                    } else {
                        return Err(Error::UnexpectedType);
                    }
                }
                OpCode::SetProperty => {
                    let obj_idx = self.read_byte()? as usize;
                    let bytes: [u8; 2] = self.read_n(2)?.try_into().unwrap();
                    let const_idx = u16::from_le_bytes(bytes) as usize;
                    let val_idx = self.read_byte()? as usize;

                    let hash = match self.constants.get(const_idx) {
                        Some(Value::Hash(h)) => *h,
                        _ => panic!("Expected hash constant"),
                    };
                    let new_val = self.stack[fp + val_idx].clone();

                    if let Value::Object(obj_ref) = &self.stack[fp + obj_idx] {
                        obj_ref.borrow_mut().insert(hash, new_val);
                    }
                }
                OpCode::SetPropertyDyn => {
                    let obj_reg = self.read_byte()? as usize;
                    let key_reg = self.read_byte()? as usize;
                    let val_reg = self.read_byte()? as usize;

                    let key_val = &self.stack[fp + key_reg];

                    let runtime_hash = key_val.get_hash();

                    let val = self.stack[fp + val_reg].clone();

                    // 4. Przypisujemy do obiektu
                    if let Value::Object(rc_map) = &self.stack[fp + obj_reg] {
                        rc_map.borrow_mut().insert(runtime_hash, val);
                    } else if let Value::Bytes(bytes_ref) = &self.stack[fp + obj_reg] {
                        let index = match key_val {
                            Value::Int(i) => *i,
                            _ => panic!("Runtime Error: Bytes index must be integer"),
                        };
                        let byte_val = match val {
                            Value::Int(i) => (i & 0xFF) as u8,
                            _ => panic!(
                                "Runtime Error: Value assigned to Bytes index must be integer byte"
                            ),
                        };
                        let mut b = bytes_ref.borrow_mut();
                        if index < 0 || (index as usize) >= b.len() {
                            panic!(
                                "Runtime Error: Bytes index out of bounds: {} (len {})",
                                index,
                                b.len()
                            );
                        }
                        b[index as usize] = byte_val;
                    } else {
                        panic!("Attempted to set property on non-object");
                    }
                }

                OpCode::GetPropertyDyn => {
                    let target_reg = self.read_byte()? as usize;
                    let obj_reg = self.read_byte()? as usize;
                    let key_reg = self.read_byte()? as usize;

                    let key_val = &self.stack[fp + key_reg];
                    let runtime_hash = key_val.get_hash();

                    let obj_val = self.stack[fp + obj_reg].clone();
                    if let Value::Object(rc_map) = obj_val {
                        let value = rc_map
                            .borrow()
                            .get(&runtime_hash)
                            .cloned()
                            .expect("Missing property from object");
                        self.stack[fp + target_reg] = value;
                    } else if let Value::EnumField { args, .. } = obj_val {
                        if let Some((_, val)) = args.iter().find(|(h, _)| *h == runtime_hash) {
                            self.stack[fp + target_reg] = val.clone();
                        } else {
                            return Err(Error::PropertyNotFound(runtime_hash));
                        }
                    } else if let Value::Bytes(bytes_ref) = obj_val {
                        let index = match key_val {
                            Value::Int(i) => *i,
                            _ => panic!("Runtime Error: Bytes index must be integer"),
                        };
                        let byte_val = {
                            let b = bytes_ref.borrow();
                            if index < 0 || (index as usize) >= b.len() {
                                panic!(
                                    "Runtime Error: Bytes index out of bounds: {} (len {})",
                                    index,
                                    b.len()
                                );
                            }
                            b[index as usize] as i64
                        };
                        self.stack[fp + target_reg] = Value::Int(byte_val);
                    } else {
                        panic!("Runtime Error: Attempted to get property from non-object");
                    }
                }
                OpCode::LoadNative => {
                    let dest = self.read_byte()? as usize;
                    let bytes: [u8; 2] = self.read_n(2)?.try_into().unwrap();
                    let hash_idx = u16::from_le_bytes(bytes) as usize;

                    let hash = match self.constants.get(hash_idx) {
                        Some(Value::Hash(h)) => Value::Hash(*h),
                        _ => panic!("Expected hash constant"),
                    };
                    let found = self
                        .native_functions
                        .iter()
                        .find(|f| {
                            Value::Hash(Value::String(f.name.to_string().into()).get_hash()) == hash
                        })
                        .unwrap()
                        .clone();
                    self.stack[fp + dest] = Value::NativeFun(found);
                }
                OpCode::LoadGlobal => {
                    let dest = self.read_byte()? as usize;

                    let global_reg = self.read_byte()? as usize;

                    let global_val = self.stack[global_reg].clone();

                    self.stack[fp + dest] = global_val;
                }
                OpCode::Inc => {
                    let src = self.read_byte()? as usize;

                    let left = self.stack[fp + src].clone();

                    self.stack[fp + src] = Self::binary(0, left, Value::Int(1));
                }
                OpCode::Dec => {
                    let src = self.read_byte()? as usize;

                    let left = self.stack[fp + src].clone();

                    self.stack[fp + src] = Self::binary(1, left, Value::Int(1));
                }
                OpCode::MatchEnum => {
                    let dest = self.read_byte()? as usize;
                    let src = self.read_byte()? as usize;
                    let bytes: [u8; 2] = self.read_n(2)?.try_into().unwrap();
                    let enum_idx = u16::from_le_bytes(bytes);
                    let tag = self.read_byte()?;
                    let matched = match &self.stack[fp + src] {
                        Value::EnumField {
                            const_idx: c,
                            tag: t,
                            ..
                        } => *c == enum_idx as usize && *t == tag,
                        _ => false,
                    };

                    self.stack[fp + dest] = Value::Bool(matched);
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
            Value::Ref(_) | Value::Hash(_) => unreachable!(),
            Value::Fun { .. } => true,
            Value::NativeFun(_) => true,
            Value::Object(items) => items.borrow().len() > 0,
            Value::EnumDefinition(_) | Value::EnumField { .. } => true,
            Value::Bytes(bytes) => bytes.borrow().len() > 0,
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
            7 => Value::Bool(left >= right),
            8 => Value::Bool(left <= right),
            9 => (left % right).expect("Unexpected error"),
            10 => (left & right).expect("Unexpected error"),
            11 => (left | right).expect("Unexpected error"),
            12 => (left ^ right).expect("Unexpected error"),
            13 => (left << right).expect("Unexpected error"),
            14 => (left >> right).expect("Unexpected error"),
            _ => panic!("UnexpectedType bin"),
        }
    }
}
