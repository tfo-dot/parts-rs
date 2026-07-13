use std::{
    cell::RefCell,
    collections::HashMap,
    process::Command,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::value::{NativeFunction, Value};
use parts_macros::native_function;

#[native_function(arity = 1)]
pub fn __println(args: Vec<Value>) -> Result<Value, String> {
    for arg in args {
        print!("{}", arg)
    }
    println!();

    Ok(Value::Bool(true))
}

#[native_function(arity = 1)]
pub fn __print(args: Vec<Value>) -> Result<Value, String> {
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
        Value::String(_) => todo!(),
        Value::Object(map) => {
            let mut hash_map = HashMap::new();

            hash_map.insert(
                Value::String("data".to_string()).get_hash(),
                Value::Object(map.clone()),
            );

            hash_map.insert(Value::String("index".to_string()).get_hash(), Value::Int(0));

            Ok(Value::Object(Rc::new(RefCell::new(hash_map))))
        }
        _ => Err("UnexpectedType, only object/strings".to_string()),
    };
}

#[native_function]
pub fn __get_next(obj: Value) -> Result<Value, String> {
    if let Value::Object(obj_ref) = obj {
        let mut map = obj_ref.borrow_mut();

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
}

#[native_function]
pub fn __has_next(obj: Value) -> Result<Value, String> {
    if let Value::Object(obj_ref) = obj {
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
    let raw_cmd = match &args[0] {
        Value::String(s) => s,
        _ => return Err("Expected string lol".to_string()),
    };

    let mut cmd = Command::new(raw_cmd);

    for arg in args.iter().skip(1) {
        let raw_arg = match arg {
            Value::String(s) => s,
            _ => return Err("Expected string lol".to_string()),
        };

        cmd.arg(raw_arg);
    }

    let res = cmd.output();

    if res.is_err() {
        Ok(Value::Int(1))
    } else {
        let output = res.unwrap();

        let s = String::from_utf8_lossy(&output.stdout);

        Ok(Value::String(s.to_string()))
    }
}

#[native_function]
pub fn __env(name: Value) -> Result<Value, String> {
    let name = match name {
        Value::String(s) => s,
        _ => return Err("Expected string lol".to_string()),
    };

    match std::env::var(name) {
        Ok(val) => Ok(Value::String(val)),
        Err(_) => Err("Some error lol".to_string()),
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

    Ok(Value::String(format!("{}{}", s1, s2)))
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
    match val {
        Value::Double(d) => Ok(Value::Double(d.floor())),
        _ => Err("Expected number".to_string()),
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
pub fn __byte_or(left: Value, right: Value) -> Result<Value, String> {
    let i1 = match left {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match right {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    return Ok(Value::Int(i1 | i2));
}

#[native_function]
pub fn __byte_and(left: Value, right: Value) -> Result<Value, String> {
    let i1 = match left {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match right {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    return Ok(Value::Int(i1 & i2));
}

#[native_function]
pub fn __byte_xor(left: Value, right: Value) -> Result<Value, String> {
    let i1 = match left {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match right {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    return Ok(Value::Int(i1 ^ i2));
}

#[native_function]
pub fn __byte_not(left: Value) -> Result<Value, String> {
    let i1 = match left {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    return Ok(Value::Int(!i1));
}

#[native_function]
pub fn __byte_shl(left: Value, right: Value) -> Result<Value, String> {
    let i1 = match left {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match right {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    return Ok(Value::Int(i1 << i2));
}

#[native_function]
pub fn __byte_shr(left: Value, right: Value) -> Result<Value, String> {
    let i1 = match left {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match right {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    return Ok(Value::Int(i1 >> i2));
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

#[derive(Clone)]
pub struct StdModule {
    pub functions: Vec<NativeFunction>,
}

impl StdModule {
    pub fn get_core() -> Self {
        Self {
            functions: vec![
                __println,
                __print,
                __timestamp,
                __iter_of,
                __get_next,
                __has_next,
                __rand,
                __exec,
                __env,
                __joinStr,
                __math_sin,
                __math_cos,
                __math_floor,
                __math_pow,
                __str_len,
                __byte_and,
                __byte_not,
                __byte_xor,
                __byte_shr,
                __byte_shl,
                __byte_or,
                __byte_rotate_left,
            ],
        }
    }
}
