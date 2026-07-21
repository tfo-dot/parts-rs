use crate::impl_binary_op;
use crate::impl_bitwise_op;
use crate::impl_compare_op;

use rustc_hash::{FxHashMap, FxHasher};
use std::cell::RefCell;
use std::fmt::Display;
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Double(f64),
    Bool(bool),
    String(Rc<String>),
    Ref(Rc<String>),
    Fun { arity: u8, body: Vec<u8> },
    NativeFun(NativeFunction),
    Object(Rc<RefCell<FxHashMap<u64, Value>>>),
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
            Value::String(s) => {
                state.write_u8(3);
                s.as_str().hash(state);
            }
            Value::Ref(s) => {
                state.write_u8(3);
                s.as_str().hash(state);
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

                let mut vm = VM::new(vec![], constants);

                for (i, arg) in args.into_iter().enumerate() {
                    vm.stack[i] = arg;
                }

                vm.run_with_frame(Frame {
                    pointer: 0,
                    ip: 0,
                    bytecode: Rc::new(body.to_vec()),
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
                let mut hasher = FxHasher::default();
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
                let mut hasher = FxHasher::default();
                self.hash(&mut hasher);
                hasher.finish()
            }
        }
    }

    pub fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            Value::Int(i) => {
                buffer.push(0);
                buffer.extend_from_slice(&i.to_le_bytes());
            }
            Value::Double(d) => {
                buffer.push(1);
                buffer.extend_from_slice(&d.to_le_bytes());
            }
            Value::Bool(b) => {
                buffer.push(2);
                buffer.push(*b as u8);
            }
            Value::String(s) => {
                buffer.push(3);
                buffer.extend_from_slice(&(s.len() as u64).to_le_bytes());
                buffer.extend_from_slice(s.as_bytes());
            }
            Value::Fun { arity, body } => {
                buffer.push(4);
                buffer.push(*arity);
                buffer.extend_from_slice(&(body.len() as u64).to_le_bytes());
                buffer.extend_from_slice(body);
            }
            Value::Object(ref_cell) => {
                buffer.push(5);
                let obj = ref_cell.borrow();
                buffer.push(obj.len() as u8);

                for (key, value) in obj.iter() {
                    buffer.push(6);
                    buffer.extend_from_slice(&key.to_le_bytes());
                    value.encode(buffer);
                }
            }
            Value::Hash(h) => {
                buffer.push(6);
                buffer.extend_from_slice(&h.to_le_bytes());
            }
            Value::NativeFun(f) => {
                buffer.push(7);
                let name_bytes = f.name.as_bytes();

                buffer.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                buffer.extend_from_slice(name_bytes);
            }
            _ => unreachable!(),
        }
    }

    pub fn decode(raw: &[u8], once: bool, starting_idx: usize) -> (Vec<Value>, usize) {
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
                    // Zgodnie z formatem zapisu, wczytujemy u64, potem as usize
                    let len = u64::from_le_bytes(len_bytes) as usize;
                    idx += 8;

                    let raw_s = &raw[idx..idx + len];
                    idx += len;
                    values.push(Value::String(
                        String::from_utf8(raw_s.to_vec()).unwrap().into(),
                    ));
                }
                4 => {
                    idx += 1;
                    let arity = raw[idx];
                    idx += 1;

                    let len_bytes: [u8; 8] = raw[idx..idx + 8].try_into().unwrap();
                    let len = u64::from_le_bytes(len_bytes) as usize;
                    idx += 8;

                    let body = &raw[idx..idx + len];
                    idx += len;

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

                    for _ in 0..count * 2 {
                        let (mut temp_vals, temp_idx) = Value::decode(raw, true, idx);
                        idx = temp_idx;
                        entries.append(&mut temp_vals);
                    }

                    let mut obj: FxHashMap<u64, Value> = FxHashMap::default();

                    for chunk in entries.chunks_exact(2) {
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
                7 => {
                    idx += 1;
                    let len_bytes: [u8; 4] = raw[idx..idx + 4].try_into().unwrap();
                    idx += 4;
                    let len = u32::from_le_bytes(len_bytes) as usize;

                    let name_bytes = &raw[idx..idx + len];
                    idx += len;

                    let std = crate::value::StdDefinition::get_core();
                    let native = std
                        .functions
                        .into_iter()
                        .find(|f| f.name.as_bytes() == name_bytes)
                        .unwrap_or_else(|| panic!("Missing native function"));

                    values.push(Value::NativeFun(native));
                }
                _ => panic!("Unexpected value type at index {}", idx),
            }

            if once {
                break;
            }
        }
        (values, idx)
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
        Value::String(v.into())
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string().into())
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

impl_bitwise_op!(BitAnd, bitand, &);
impl_bitwise_op!(BitOr, bitor, |);
impl_bitwise_op!(BitXor, bitxor, ^);
impl_bitwise_op!(Shl, shl, <<);
impl_bitwise_op!(Shr, shr, >>);

impl_compare_op!(op_gt, >);
impl_compare_op!(op_lt, <);

// Native

pub type NativeFn = Rc<dyn Fn(Vec<Value>) -> Result<Value, String>>;

#[derive(Clone)]
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

use core::fmt::Debug;
impl Debug for NativeFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "NativeFunction - {}", self.name)
    }
}

#[derive(Clone)]
pub struct StdDefinition {
    pub functions: Vec<NativeFunction>,
}

impl StdDefinition {
    pub fn get_core() -> Self {
        use crate::std::StdModule;

        return StdDefinition {
            functions: StdModule::get_core().functions,
        };
    }
}
