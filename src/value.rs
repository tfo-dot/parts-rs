use crate::impl_binary_op;
use crate::impl_compare_op;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Display;
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Double(f64),
    Bool(bool),
    String(String),
    Ref(String),
    Fun { arity: u8, body: Vec<u8> },
    NativeFun(NativeFunction),
    Object(Rc<RefCell<HashMap<u64, Value>>>),
    Hash(u64),
}

use std::hash::{Hash, Hasher};

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Value::Int(i) => {
                state.write_u8(0);
                i.hash(state);
            }
            Value::Double(d) => {
                state.write_u8(1);
                state.write_u64(d.to_bits());
            }
            Value::Bool(b) => {
                state.write_u8(2);
                b.hash(state);
            }
            Value::String(s) | Value::Ref(s) => {
                state.write_u8(3);
                s.hash(state);
            }
            Value::Object(obj) => {
                state.write_u8(4);
                let ptr = Rc::as_ptr(obj) as usize;
                ptr.hash(state);
            }
            Value::Fun { .. } | Value::NativeFun(_) => {
                state.write_u8(4);
                let ptr = self as *const _ as usize;
                ptr.hash(state);
            }
            Value::Hash(v) => {
                state.write_u8(5);
                v.hash(state);
            }
        }
    }
}

use std::ops::Rem;

impl Rem for Value {
    type Output = Result<Value, String>;

    fn rem(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Value::Int(a), Value::Int(b)) => {
                if b == 0 {
                    Err("remainder by zero".to_string())
                } else {
                    Ok(Value::Int(a % b))
                }
            }
            (l, r) => Err(format!("operation not supported - mod ({:?}, {:?})", l, r)),
        }
    }
}

impl Value {
    pub fn call(&self, args: Vec<Value>, constants: Vec<Value>) -> Result<Option<Value>, String> {
        match self {
            Value::Fun { arity, body } => {
                if args.len() != *arity as usize {
                    return Err(format!("Expected {} arguments, got {}", arity, args.len()));
                }

                use crate::vm::{Frame, VM};
                let mut registers = [const { Value::Int(0) }; 256];
                for (i, arg) in args.into_iter().enumerate() {
                    registers[i] = arg;
                }

                let mut vm = VM::new(vec![], constants);

                vm.run_with_frame(Frame {
                    registers,
                    ip: 0,
                    bytecode: body.clone(),
                    return_reg: 0,
                })
                .map_err(|e| format!("VM Error: {:?}", e))
            }
            Value::NativeFun(native) => {
                if args.len() != native.arity as usize {
                    return Err(format!(
                        "Expected {} arguments, got {}",
                        native.arity,
                        args.len()
                    ));
                }
                (native.call)(args).map(Some)
            }
            _ => Err("Value is not callable".to_string()),
        }
    }

    pub fn get_hash(&self) -> u64 {
        match self {
            Value::Int(i) => *i as u64,
            Value::String(s) | Value::Ref(s) => {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                s.hash(&mut hasher);
                hasher.finish()
            }
            Value::Bool(b) => {
                if *b {
                    1
                } else {
                    0
                }
            }
            _ => {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                self.hash(&mut hasher);
                hasher.finish()
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Value::Int(i) => {
                let mut tmp = vec![0];
                let mut encoded: Vec<_> = i.to_le_bytes().into();

                tmp.append(&mut encoded);

                return tmp;
            }
            Value::Double(d) => {
                let mut tmp = vec![1];
                let mut encoded: Vec<_> = d.to_le_bytes().into();

                tmp.append(&mut encoded);

                return tmp;
            }
            Value::Bool(b) => vec![2, *b as u8],
            Value::String(s) => {
                let mut tmp = vec![3];

                let mut s_size: Vec<_> = s.len().to_le_bytes().into();

                tmp.append(&mut s_size);

                let mut encoded: Vec<_> = s.bytes().collect();

                tmp.append(&mut encoded);

                return tmp;
            }
            Value::Fun { arity, body } => {
                let mut tmp = vec![4];

                tmp.push(*arity);

                let mut b_size: Vec<_> = body.len().to_le_bytes().into();

                tmp.append(&mut b_size);

                let mut body_vec = body.clone();

                tmp.append(&mut body_vec);

                return tmp;
            }
            Value::Object(ref_cell) => {
                let mut tmp = vec![5];

                let obj = ref_cell.borrow();

                tmp.push(obj.len() as u8);

                for (key, value) in obj.iter() {
                    tmp.push(6);

                    let mut encoded: Vec<_> = key.to_le_bytes().into();

                    tmp.append(&mut encoded);

                    let mut encoded_val = value.encode();

                    tmp.append(&mut encoded_val);
                }

                return tmp;
            }
            Value::Hash(h) => {
                let mut tmp = vec![6];
                let mut encoded: Vec<_> = h.to_le_bytes().into();

                tmp.append(&mut encoded);

                return tmp;
            }
            _ => unreachable!(),
        }
    }

    pub fn decode(raw: Vec<u8>, once: bool, starting_idx: usize) -> (Vec<Value>, usize) {
        let mut values = vec![];

        let mut idx = starting_idx;

        while idx < raw.len() {
            match raw[idx] {
                0 => {
                    idx += 1;

                    let bytes: [u8; 8] = raw[idx..idx + 8].try_into().unwrap();

                    idx += 8;

                    values.push(Value::Int(i64::from_le_bytes(bytes)));
                }
                1 => {
                    idx += 1;

                    let bytes: [u8; 8] = raw[idx..idx + 8].try_into().unwrap();

                    idx += 8;

                    values.push(Value::Double(f64::from_le_bytes(bytes)));
                }
                2 => {
                    idx += 1;

                    let val = raw[idx];

                    idx += 1;

                    values.push(Value::Bool(val != 0));
                }
                3 => {
                    idx += 1;

                    let len_bytes: [u8; 8] = raw[idx..idx + 8].try_into().unwrap();

                    let len = i64::from_le_bytes(len_bytes);

                    idx += 8;

                    let raw_s = &raw[idx..idx + len as usize];

                    idx += len as usize;

                    values.push(Value::String(String::from_utf8(raw_s.to_vec()).unwrap()));
                }
                4 => {
                    idx += 1;

                    let arity = raw[idx];

                    idx += 1;

                    let len_bytes: [u8; 8] = raw[idx..idx + 8].try_into().unwrap();

                    let len = i64::from_le_bytes(len_bytes);

                    idx += 8;

                    let body = &raw[idx..idx + len as usize];

                    idx += len as usize;

                    values.push(Value::Fun {
                        arity,
                        body: body.to_vec(),
                    });
                }
                5 => {
                    idx += 1;

                    let count = raw[idx];

                    idx += 1;

                    let mut entries = vec![];

                    for _counter in 0..count * 2 {
                        let (mut temp_vals, temp_idx) = Value::decode(raw.clone(), true, idx);

                        idx = temp_idx;

                        entries.append(&mut temp_vals);
                    }

                    let mut obj: HashMap<u64, Value> = HashMap::new();

                    for chunk in entries.chunks_exact(2).into_iter() {
                        let key_raw = match chunk[0] {
                            Value::Hash(h) => h,
                            _ => unreachable!(),
                        };

                        obj.insert(key_raw, chunk[1].clone());
                    }

                    values.push(Value::Object(Rc::new(RefCell::new(obj))));
                }
                6 => {
                    idx += 1;

                    let bytes: [u8; 8] = raw[idx..idx + 8].try_into().unwrap();

                    idx += 8;

                    values.push(Value::Hash(u64::from_le_bytes(bytes)));
                }
                _ => panic!("Unexpected value type"),
            }

            if once {
                break;
            }
        }
        return (values, idx);
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Double(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string())
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        return match (self, other) {
            (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
            (Value::Int(a), Value::Double(b)) => (*a as f64).partial_cmp(b),
            (Value::Double(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)),
            (Value::Double(a), Value::Double(b)) => a.partial_cmp(b),
            (Value::String(a), Value::String(b)) => a.partial_cmp(b),
            _ => Some(std::cmp::Ordering::Equal),
        };
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{}", i),
            Value::Double(d) => write!(f, "{}", d),
            Value::Bool(b) => write!(f, "{}", b),
            Value::String(s) => write!(f, "{}", s), // Quoted for clarity
            Value::Ref(r) => write!(f, "&{}", r),   // Prefixed with & to show it's a ref
            Value::Fun { arity, .. } => write!(f, "<function/{}>", arity),
            Value::NativeFun(_) => write!(f, "{}", "<native fun>"),
            Value::Object(obj) => write!(f, "<object: {} keys>", obj.borrow().len()),
            Value::Hash(h) => write!(f, "#{}", h),
        }
    }
}

impl_binary_op!(Add, add, +);
impl_binary_op!(Sub, sub, -);
impl_binary_op!(Mul, mul, *);
impl_binary_op!(Div, div, /);

impl_compare_op!(op_gt, >);
impl_compare_op!(op_lt, <);

// Native

pub type NativeFn = fn(args: Vec<Value>) -> Result<Value, String>;

#[derive(Clone, Debug)]
pub struct NativeFunction {
    pub name: &'static str,
    pub arity: u8,
    pub call: NativeFn,
}

impl PartialEq for NativeFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.arity == other.arity
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct NativeFunctionDef {
    pub name: &'static str,
    pub arity: u8,
}

#[derive(Clone)]
pub struct StdDefinition {
    pub functions: Vec<NativeFunctionDef>,
}

impl StdDefinition {
    pub fn get_core() -> Self {
        use crate::std::StdModule;

        return StdDefinition {
            functions: {
                StdModule::get_core()
                    .functions
                    .iter()
                    .map(|f| {
                        return NativeFunctionDef {
                            name: f.name,
                            arity: f.arity,
                        };
                    })
                    .collect()
            },
        };
    }
}
