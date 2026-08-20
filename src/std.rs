use rustc_hash::FxHashMap;
use std::{
    cell::RefCell,
    process::Command,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::value::{NativeFunction, Value};
use parts_macros::native_function;

#[native_function(arity = 1)]
pub fn println(args: Vec<Value>) -> Result<Value, String> {
    for arg in args {
        print!("{}", arg)
    }
    println!();

    Ok(Value::Bool(true))
}

#[native_function(arity = 1)]
pub fn print(args: Vec<Value>) -> Result<Value, String> {
    for arg in args {
        print!("{}", arg)
    }

    Ok(Value::Bool(true))
}


#[native_function]
pub fn __timestamp() -> Result<Value, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros();

    Ok(Value::Int(ts as i64))
}

#[native_function]
pub fn __iter_of(val: Value) -> Result<Value, String> {
    return match val {
        Value::String(s) => {
            let mut hash_map = FxHashMap::default();

            hash_map.insert(
                Value::String("data".to_string().into()).get_hash(),
                Value::String(s.clone()),
            );

            hash_map.insert(
                Value::String("index".to_string().into()).get_hash(),
                Value::Int(0),
            );

            Ok(Value::Object(Rc::new(RefCell::new(hash_map))))
        }
        Value::Object(map) => {
            let mut hash_map = FxHashMap::default();

            hash_map.insert(
                Value::String("data".to_string().into()).get_hash(),
                Value::Object(map.clone()),
            );

            hash_map.insert(
                Value::String("index".to_string().into()).get_hash(),
                Value::Int(0),
            );

            Ok(Value::Object(Rc::new(RefCell::new(hash_map))))
        }
        _ => Err("UnexpectedType, only object/strings".to_string()),
    };
}

#[native_function]
pub fn __get_next(obj: Value) -> Result<Value, String> {
    if let Value::Object(obj_ref) = obj {
        let mut map = obj_ref.borrow_mut();

        let data_hash = Value::String("data".to_string().into()).get_hash();
        let index_hash = Value::String("index".to_string().into()).get_hash();

        let data = map.get(&data_hash).cloned().ok_or("Missing data")?;
        let index = if let Some(Value::Int(i)) = map.get(&index_hash) {
            *i
        } else {
            0
        };

        match data {
            Value::String(s) => {
                if s.len() < index as usize {
                    return Ok(Value::Bool(false));
                }

                let ch = s.chars().nth(index as usize).expect("Shouldn't be empty");

                map.insert(index_hash, Value::Int(index + 1));

                return Ok(Value::String(ch.to_string().into()));
            }
            Value::Object(items_ref) => {
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
            _ => (),
        }

        Ok(Value::Bool(false))
    } else {
        Err("UnexpectedType, expected object".to_string())
    }
}

#[native_function]
pub fn __has_next(obj: Value) -> Result<Value, String> {
    if let Value::Object(obj_ref) = obj {
        let map = obj_ref.borrow();

        let data_hash = Value::String("data".to_string().into()).get_hash();
        let index_hash = Value::String("index".to_string().into()).get_hash();

        let data = map.get(&data_hash).cloned().ok_or("Missing data")?;
        let index = if let Some(Value::Int(i)) = map.get(&index_hash) {
            *i
        } else {
            0
        };

        match data {
            Value::String(s) => return Ok(Value::Bool(s.len() > index as usize)),
            Value::Object(items_ref) => {
                let items = items_ref.borrow();

                let entry_hash = items.keys().nth(index as usize);

                if entry_hash.is_none() {
                    return Ok(Value::Bool(false));
                }

                return Ok(Value::Bool(items.get(&entry_hash.unwrap()).is_some()));
            }
            _ => (),
        }

        Ok(Value::Bool(false))
    } else {
        Err("UnexpectedType, expected object".to_string())
    }
}

#[native_function]
pub fn __rand() -> Result<Value, String> {
    let a = 1103515245;
    let c = 12345;
    let m = 2147483648;

    let seed_source = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros();

    Ok(Value::Int(((a * seed_source) + c % m) as i64))
}

#[native_function(arity = 1)]
pub fn __exec(args: Vec<Value>) -> Result<Value, String> {
    let raw_cmd = match args.first() {
        Some(Value::String(s)) => s,
        _ => return Ok(Value::err("Expected string command for exec")),
    };

    let mut cmd = Command::new(raw_cmd.as_str());

    for arg in args.iter().skip(1) {
        let raw_arg = match arg {
            Value::String(s) => s,
            _ => return Ok(Value::err("Expected string argument for exec")),
        };

        cmd.arg(raw_arg.as_str());
    }

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout);
                Ok(Value::ok(Value::String(s.to_string().into())))
            } else {
                let err_s = String::from_utf8_lossy(&output.stderr);
                let err_msg = if !err_s.is_empty() {
                    err_s.to_string()
                } else {
                    format!("Command exited with status code: {:?}", output.status.code())
                };
                Ok(Value::err(Value::String(err_msg.into())))
            }
        }
        Err(e) => Ok(Value::err(Value::String(
            format!("Command execution failed: {}", e).into(),
        ))),
    }
}

#[native_function]
pub fn __env(name: Value) -> Result<Value, String> {
    let name = match name {
        Value::String(s) => s,
        _ => return Ok(Value::err("Expected string argument for env")),
    };

    match std::env::var(name.as_str()) {
        Ok(val) => Ok(Value::ok(Value::String(val.into()))),
        Err(e) => Ok(Value::err(Value::String(
            format!("Environment variable not found: {}", e).into(),
        ))),
    }
}

#[native_function]
pub fn __joinStr(arg_one: Value, arg_two: Value) -> Result<Value, String> {
    let s1 = match arg_one {
        Value::String(s) => s,
        _ => return Err("Expected string lol".to_string()),
    };

    let s2 = match arg_two {
        Value::String(s) => s,
        _ => return Err("Expected string lol".to_string()),
    };

    Ok(Value::String(format!("{}{}", s1, s2).into()))
}

#[native_function]
pub fn __math_sin(val: Value) -> Result<Value, String> {
    match val {
        Value::Double(d) => Ok(Value::Double(d.sin())),
        Value::Int(i) => Ok(Value::Double((i as f64).sin())),
        _ => Err("Expected number".to_string()),
    }
}

#[native_function]
pub fn __math_cos(val: Value) -> Result<Value, String> {
    match val {
        Value::Double(d) => Ok(Value::Double(d.cos())),
        Value::Int(i) => Ok(Value::Double((i as f64).cos())),
        _ => Err("Expected number".to_string()),
    }
}

#[native_function]
pub fn __math_floor(val: Value) -> Result<Value, String> {
    if let Value::Double(d) = val {
        Ok(Value::Int(d.floor() as i64))
    } else if let Value::Int(i) = val {
        Ok(Value::Int(i))
    } else {
        Err("Expected double or int for math.floor".into())
    }
}

#[native_function]
pub fn __math_pow(exp: Value, pow: Value) -> Result<Value, String> {
    let i1 = match exp {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match pow {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    return Ok(Value::Int(i1.pow(i2 as u32)));
}

#[native_function]
pub fn __str_len(val: Value) -> Result<Value, String> {
    match val {
        Value::String(s) => Ok(Value::Int(s.len() as i64)),
        _ => Err("Expected string".to_string()),
    }
}

#[native_function]
pub fn __str_strip_prefix(str: Value, prefix: Value) -> Result<Value, String> {
    let s1 = match str {
        Value::String(s) => s,
        _ => return Ok(Value::none()),
    };

    let s2 = match prefix {
        Value::String(s) => s,
        _ => return Ok(Value::none()),
    };

    if s1.starts_with(&*s2) {
        Ok(Value::some(Value::String(
            s1.strip_prefix(&*s2).unwrap().to_string().into(),
        )))
    } else {
        Ok(Value::none())
    }
}

#[native_function]
pub fn __str_strip_suffix(str: Value, suffix: Value) -> Result<Value, String> {
    let s1 = match str {
        Value::String(s) => s,
        _ => return Ok(Value::none()),
    };

    let s2 = match suffix {
        Value::String(s) => s,
        _ => return Ok(Value::none()),
    };

    if s1.ends_with(&*s2) {
        Ok(Value::some(Value::String(
            s1.strip_suffix(&*s2).unwrap().to_string().into(),
        )))
    } else {
        Ok(Value::none())
    }
}

#[native_function]
pub fn __str_upper(val: Value) -> Result<Value, String> {
    match val {
        Value::String(s) => Ok(Value::String(s.to_uppercase().into())),
        _ => Err("Expected string".to_string()),
    }
}

#[native_function]
pub fn __str_lower(val: Value) -> Result<Value, String> {
    match val {
        Value::String(s) => Ok(Value::String(s.to_lowercase().into())),
        _ => Err("Expected string".to_string()),
    }
}

#[native_function]
pub fn __byte_rotate_left(left: Value, right: Value, mask: Value) -> Result<Value, String> {
    let i1 = match left {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match right {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let mask_raw = match mask {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let x = match mask_raw {
        0 => (i1 as u8).rotate_left(i2 as u32) as i64,
        1 => (i1 as u16).rotate_left(i2 as u32) as i64,
        2 => (i1 as u32).rotate_left(i2 as u32) as i64,
        3 => (i1 as u64).rotate_left(i2 as u32) as i64,
        _ => return Err("Value out of expected range".to_string()),
    };

    return Ok(Value::Int(x));
}

#[native_function]
pub fn __object_len(obj: Value) -> Result<Value, String> {
    if let Value::Object(obj_ref) = obj {
        Ok(Value::Int(obj_ref.take().len() as i64))
    } else {
        Err("UnexpectedType, expected object".to_string())
    }
}

#[native_function]
pub fn __str_byte_at(str: Value, idx: Value) -> Result<Value, String> {
    let s = match str {
        Value::String(s) => s,
        _ => return Ok(Value::err("Expected string for byte_at")),
    };

    let index = match idx {
        Value::Int(i) => i,
        _ => return Ok(Value::err("Expected integer for byte_at index")),
    };

    if index < 0 {
        return Ok(Value::err("Negative index in byte_at"));
    }

    if let Some(ch) = s.chars().nth(index as usize) {
        Ok(Value::ok(Value::Int((ch as i64).try_into().unwrap())))
    } else {
        Ok(Value::err("Index out of bounds in byte_at"))
    }
}

fn result_is_ok(val: Value) -> Result<Value, String> {
    Ok(Value::Bool(val.is_ok()))
}

fn result_is_err(val: Value) -> Result<Value, String> {
    Ok(Value::Bool(val.is_err()))
}

fn option_is_some(val: Value) -> Result<Value, String> {
    Ok(Value::Bool(val.is_some()))
}

fn option_is_none(val: Value) -> Result<Value, String> {
    Ok(Value::Bool(val.is_none()))
}

fn unwrap_val(val: Value) -> Result<Value, String> {
    match val {
        Value::EnumField { const_idx: 0, tag: 0, args } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err("Result::Ok had no value".to_string())
            }
        }
        Value::EnumField { const_idx: 0, tag: 1, args } => {
            let err_msg = args.first().map(|(_, v)| v.to_string()).unwrap_or_else(|| "Error".to_string());
            Err(format!("called `unwrap()` on an `Err` value: {}", err_msg))
        }
        Value::EnumField { const_idx: 1, tag: 0, args } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err("Option::Some had no value".to_string())
            }
        }
        Value::EnumField { const_idx: 1, tag: 1, .. } => {
            Err("called `unwrap()` on a `None` value".to_string())
        }
        _ => Err("called `unwrap()` on non-Result/non-Option value".to_string()),
    }
}

fn unwrap_or_val(val: Value, default: Value) -> Result<Value, String> {
    match val {
        Value::EnumField { const_idx: 0, tag: 0, args }
        | Value::EnumField { const_idx: 1, tag: 0, args } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Ok(default)
            }
        }
        _ => Ok(default),
    }
}

fn expect_val(val: Value, msg: Value) -> Result<Value, String> {
    let msg_str = match &msg {
        Value::String(s) => s.to_string(),
        _ => format!("{}", msg),
    };
    match val {
        Value::EnumField { const_idx: 0, tag: 0, args }
        | Value::EnumField { const_idx: 1, tag: 0, args } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err(format!("{}: value was empty", msg_str))
            }
        }
        Value::EnumField { const_idx: 0, tag: 1, args } => {
            let err_msg = args.first().map(|(_, v)| v.to_string()).unwrap_or_else(|| "Error".to_string());
            Err(format!("{}: {}", msg_str, err_msg))
        }
        Value::EnumField { const_idx: 1, tag: 1, .. } => {
            Err(format!("{}: None", msg_str))
        }
        _ => Err(format!("{}: called expect on non-Result/non-Option value", msg_str)),
    }
}

fn unwrap_err_val(val: Value) -> Result<Value, String> {
    match val {
        Value::EnumField { const_idx: 0, tag: 1, args } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err("Result::Err had no error content".to_string())
            }
        }
        Value::EnumField { const_idx: 0, tag: 0, args } => {
            let val_str = args.first().map(|(_, v)| v.to_string()).unwrap_or_else(|| "".to_string());
            Err(format!("called `unwrap_err()` on an `Ok` value: {}", val_str))
        }
        _ => Err("called `unwrap_err()` on non-Result value".to_string()),
    }
}

fn option_ok_or(val: Value, err: Value) -> Result<Value, String> {
    match val {
        Value::EnumField { const_idx: 1, tag: 0, args } => {
            if let Some((_, v)) = args.first() {
                Ok(Value::ok(v.clone()))
            } else {
                Ok(Value::err(err))
            }
        }
        _ => Ok(Value::err(err)),
    }
}

fn result_to_ok(val: Value) -> Result<Value, String> {
    match val {
        Value::EnumField { const_idx: 0, tag: 0, args } => {
            if let Some((_, v)) = args.first() {
                Ok(Value::some(v.clone()))
            } else {
                Ok(Value::none())
            }
        }
        Value::EnumField { const_idx: 0, tag: 1, .. } => Ok(Value::none()),
        _ => Ok(Value::ok(val)),
    }
}

fn result_to_err(val: Value) -> Result<Value, String> {
    match val {
        Value::EnumField { const_idx: 0, tag: 1, args } => {
            if let Some((_, e)) = args.first() {
                Ok(Value::some(e.clone()))
            } else {
                Ok(Value::none())
            }
        }
        Value::EnumField { const_idx: 0, tag: 0, .. } => Ok(Value::none()),
        _ => Ok(Value::err(val)),
    }
}

#[native_function]
pub fn __result_is_ok(val: Value) -> Result<Value, String> {
    result_is_ok(val)
}

#[native_function]
pub fn is_ok(val: Value) -> Result<Value, String> {
    result_is_ok(val)
}

#[native_function]
pub fn __result_is_err(val: Value) -> Result<Value, String> {
    result_is_err(val)
}

#[native_function]
pub fn is_err(val: Value) -> Result<Value, String> {
    result_is_err(val)
}

#[native_function]
pub fn __option_is_some(val: Value) -> Result<Value, String> {
    option_is_some(val)
}

#[native_function]
pub fn is_some(val: Value) -> Result<Value, String> {
    option_is_some(val)
}

#[native_function]
pub fn __option_is_none(val: Value) -> Result<Value, String> {
    option_is_none(val)
}

#[native_function]
pub fn is_none(val: Value) -> Result<Value, String> {
    option_is_none(val)
}

#[native_function]
pub fn __result_unwrap(val: Value) -> Result<Value, String> {
    unwrap_val(val)
}

#[native_function]
pub fn unwrap(val: Value) -> Result<Value, String> {
    unwrap_val(val)
}

#[native_function]
pub fn __result_unwrap_or(val: Value, default: Value) -> Result<Value, String> {
    unwrap_or_val(val, default)
}

#[native_function]
pub fn unwrap_or(val: Value, default: Value) -> Result<Value, String> {
    unwrap_or_val(val, default)
}

#[native_function]
pub fn __result_expect(val: Value, msg: Value) -> Result<Value, String> {
    expect_val(val, msg)
}

#[native_function]
pub fn expect(val: Value, msg: Value) -> Result<Value, String> {
    expect_val(val, msg)
}

#[native_function]
pub fn __result_unwrap_err(val: Value) -> Result<Value, String> {
    unwrap_err_val(val)
}

#[native_function]
pub fn unwrap_err(val: Value) -> Result<Value, String> {
    unwrap_err_val(val)
}

#[native_function]
pub fn __option_ok_or(val: Value, err: Value) -> Result<Value, String> {
    option_ok_or(val, err)
}

#[native_function]
pub fn ok_or(val: Value, err: Value) -> Result<Value, String> {
    option_ok_or(val, err)
}

#[native_function]
pub fn __result_ok(val: Value) -> Result<Value, String> {
    result_to_ok(val)
}

#[native_function]
pub fn ok(val: Value) -> Result<Value, String> {
    result_to_ok(val)
}

#[native_function]
pub fn __result_err(err: Value) -> Result<Value, String> {
    result_to_err(err)
}

#[native_function]
pub fn err(err: Value) -> Result<Value, String> {
    result_to_err(err)
}

#[native_function]
pub fn __option_some(val: Value) -> Result<Value, String> {
    Ok(Value::some(val))
}

#[native_function]
pub fn some(val: Value) -> Result<Value, String> {
    Ok(Value::some(val))
}

#[native_function]
pub fn __option_none() -> Result<Value, String> {
    Ok(Value::none())
}

#[native_function]
pub fn none() -> Result<Value, String> {
    Ok(Value::none())
}
pub static EXTRA_NATIVES: std::sync::OnceLock<std::sync::Mutex<Vec<NativeFunction>>> = std::sync::OnceLock::new();

pub fn register_extra_native(name: &'static str, arity: u8, call: fn(args: Vec<Value>) -> Result<Value, String>) {
    let native = NativeFunction {
        name,
        arity,
        call: std::sync::Arc::new(call),
    };
    EXTRA_NATIVES
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .push(native);
}

#[derive(Clone)]
pub struct StdModule {
    pub functions: Vec<NativeFunction>,
}

impl StdModule {
    pub fn get_core() -> Self {
        let mut functions = vec![
            println(),
            print(),
            __timestamp(),
            __iter_of(),
            __get_next(),
            __has_next(),
            __rand(),
            __exec(),
            __env(),
            __joinStr(),
            __math_sin(),
            __math_cos(),
            __math_floor(),
            __math_pow(),
            __str_len(),
            __str_strip_prefix(),
            __str_strip_suffix(),
            __str_lower(),
            __str_upper(),
            __str_byte_at(),
            __byte_rotate_left(),
            __object_len(),
            __result_is_ok(),
            __result_is_err(),
            __option_is_some(),
            __option_is_none(),
            __result_unwrap(),
            __result_unwrap_or(),
            __result_expect(),
            __result_unwrap_err(),
            __option_ok_or(),
            __result_ok(),
            __result_err(),
            __option_some(),
            __option_none(),
            is_ok(),
            is_err(),
            is_some(),
            is_none(),
            unwrap(),
            unwrap_or(),
            expect(),
            unwrap_err(),
            ok_or(),
            ok(),
            err(),
            some(),
            none(),
        ];
        
        if let Some(extra) = EXTRA_NATIVES.get() {
            if let Ok(guard) = extra.lock() {
                functions.extend((*guard).clone());
            }
        }

        Self { functions }
    }
}
