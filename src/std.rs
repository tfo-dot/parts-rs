use rustc_hash::FxHashMap;
use std::{
    cell::RefCell,
    io::{Read, Write},
    net::TcpStream,
    os::unix::net::UnixStream,
    process::Command,
    rc::Rc,
    sync::Mutex,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

enum SocketStream {
    Tcp(TcpStream),
    Tls(native_tls::TlsStream<TcpStream>),
    Unix(UnixStream),
}

static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(1);
static SOCKETS: std::sync::LazyLock<Mutex<FxHashMap<u64, SocketStream>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

fn get_sockets() -> &'static Mutex<FxHashMap<u64, SocketStream>> {
    &SOCKETS
}
use crate::value::{NativeFunction, Value};
use parts_macros::{native_function, parts_std};
use rustc_hash::FxHasher;
use std::sync::LazyLock;

fn raw_println(args: &[Value]) -> Result<Value, String> {
    for arg in args {
        print!("{}", arg)
    }
    println!();
    Ok(Value::Bool(true))
}

fn raw_print(args: &[Value]) -> Result<Value, String> {
    for arg in args {
        print!("{}", arg)
    }
    Ok(Value::Bool(true))
}

fn raw_timestamp() -> Result<Value, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros();
    Ok(Value::Int(ts as i64))
}

fn raw_iter_of(val: Value) -> Result<Value, String> {
    match val {
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
    }
}

fn raw_get_next(obj: Value) -> Result<Value, String> {
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

                if let Some(val) = items.get(entry_hash.unwrap()) {
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

fn raw_has_next(obj: Value) -> Result<Value, String> {
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

                return Ok(Value::Bool(true));
            }
            _ => (),
        }

        Ok(Value::Bool(false))
    } else {
        Err("UnexpectedType, expected object".to_string())
    }
}

#[cfg(unix)]
fn get_os_random_bytes(buffer: &mut [u8]) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/urandom")?;
    file.read_exact(buffer)?;
    Ok(())
}

#[cfg(windows)]
fn get_os_random_bytes(buffer: &mut [u8]) -> std::io::Result<()> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "BCryptGenRandom failed",
        ))
    }
}

static RAND_STATE: Mutex<[u64; 2]> = Mutex::new([0, 0]);

fn raw_rand() -> Result<Value, String> {
    let mut state = RAND_STATE.lock().unwrap();

    if state[0] == 0 && state[1] == 0 {
        let mut buffer = [0u8; 8];

        let seed = match get_os_random_bytes(&mut buffer) {
            Ok(_) => u64::from_ne_bytes(buffer),
            Err(e) => return Err(format!("Failed to fetch OS entropy: {}", e)),
        };

        let negated = seed.wrapping_neg();

        fn fmix64(mut k: u64) -> u64 {
            k ^= k >> 33;
            k = k.wrapping_mul(0xff51afd7ed558ccd);

            k ^= k >> 33;
            k = k.wrapping_mul(0xc4ceb9fe1a85ec53);

            k ^= k >> 33;

            k
        }

        state[0] = fmix64(seed);
        state[0] = fmix64(negated);
    }

    let mut s1 = state[0];
    let s0 = state[1];

    state[0] = s0;

    s1 ^= s1 << 23;
    state[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);

    let mantissa = state[0].wrapping_add(state[1]) >> 11;

    let result = (mantissa as f64) * (1.0 / (1u64 << 53) as f64);

    Ok(Value::Double(result))
}

fn raw_exec(args: &[Value]) -> Result<Value, String> {
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
                    format!(
                        "Command exited with status code: {:?}",
                        output.status.code()
                    )
                };
                Ok(Value::err(Value::String(err_msg.into())))
            }
        }
        Err(e) => Ok(Value::err(Value::String(
            format!("Command execution failed: {}", e).into(),
        ))),
    }
}

fn raw_env(name: Value) -> Result<Value, String> {
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

fn raw_join_str(arg_one: Value, arg_two: Value) -> Result<Value, String> {
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

fn raw_math_sin(val: Value) -> Result<Value, String> {
    match val {
        Value::Double(d) => Ok(Value::Double(d.sin())),
        Value::Int(i) => Ok(Value::Double((i as f64).sin())),
        _ => Err("Expected number".to_string()),
    }
}

fn raw_math_cos(val: Value) -> Result<Value, String> {
    match val {
        Value::Double(d) => Ok(Value::Double(d.cos())),
        Value::Int(i) => Ok(Value::Double((i as f64).cos())),
        _ => Err("Expected number".to_string()),
    }
}

fn raw_math_floor(val: Value) -> Result<Value, String> {
    if let Value::Double(d) = val {
        Ok(Value::Int(d.floor() as i64))
    } else if let Value::Int(i) = val {
        Ok(Value::Int(i))
    } else {
        Err("Expected double or int for math.floor".into())
    }
}

fn raw_math_pow(exp: Value, pow: Value) -> Result<Value, String> {
    let i1 = match exp {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    let i2 = match pow {
        Value::Int(i) => i,
        _ => return Err("Expected int lol".to_string()),
    };

    Ok(Value::Int(i1.pow(i2 as u32)))
}

fn raw_str_len(val: Value) -> Result<Value, String> {
    match val {
        Value::String(s) => Ok(Value::Int(s.len() as i64)),
        _ => Err("Expected string".to_string()),
    }
}

fn raw_str_strip_prefix(str: Value, prefix: Value) -> Result<Value, String> {
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


fn raw_str_strip_suffix(str: Value, suffix: Value) -> Result<Value, String> {
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


fn raw_str_upper(val: Value) -> Result<Value, String> {
    match val {
        Value::String(s) => Ok(Value::String(s.to_uppercase().into())),
        _ => Err("Expected string".to_string()),
    }
}


fn raw_str_lower(val: Value) -> Result<Value, String> {
    match val {
        Value::String(s) => Ok(Value::String(s.to_lowercase().into())),
        _ => Err("Expected string".to_string()),
    }
}


fn raw_byte_rotate_left(left: Value, right: Value, mask: Value) -> Result<Value, String> {
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

    Ok(Value::Int(x))
}

fn raw_object_len(obj: Value) -> Result<Value, String> {
    let target = match &obj {
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            args,
        } => args.first().map(|(_, v)| v).unwrap_or(&obj),
        _ => &obj,
    };
    if let Value::Object(obj_ref) = target {
        Ok(Value::Int(obj_ref.borrow().len() as i64))
    } else if let Value::Bytes(bytes_ref) = target {
        Ok(Value::Int(bytes_ref.borrow().len() as i64))
    } else if let Value::String(s) = target {
        Ok(Value::Int(s.len() as i64))
    } else {
        Err("UnexpectedType, expected object, bytes or string".to_string())
    }
}


fn raw_str_byte_at(str: Value, idx: Value) -> Result<Value, String> {
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
        Ok(Value::ok(Value::Int(ch as i64)))
    } else {
        Ok(Value::err("Index out of bounds in byte_at"))
    }
}


fn result_is_ok(val: Value) -> Result<Value, String> {
    match &val {
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            ..
        } => Ok(Value::Bool(true)),
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            ..
        } => Ok(Value::Bool(false)),
        _ => Ok(Value::Bool(true)),
    }
}

fn result_is_err(val: Value) -> Result<Value, String> {
    match &val {
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            ..
        } => Ok(Value::Bool(true)),
        _ => Ok(Value::Bool(false)),
    }
}

fn option_is_some(val: Value) -> Result<Value, String> {
    Ok(Value::Bool(val.is_some()))
}

fn option_is_none(val: Value) -> Result<Value, String> {
    Ok(Value::Bool(val.is_none()))
}

fn unwrap_val(val: Value) -> Result<Value, String> {
    match val {
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            args,
        } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err("Result::Ok had no value".to_string())
            }
        }
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            args,
        } => {
            let err_msg = args
                .first()
                .map(|(_, v)| v.to_string())
                .unwrap_or_else(|| "Error".to_string());
            Err(format!("called `unwrap()` on an `Err` value: {}", err_msg))
        }
        Value::EnumField {
            const_idx: 1,
            tag: 0,
            args,
        } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err("Option::Some had no value".to_string())
            }
        }
        Value::EnumField {
            const_idx: 1,
            tag: 1,
            ..
        } => Err("called `unwrap()` on a `None` value".to_string()),
        other => Ok(other),
    }
}

fn unwrap_or_val(val: Value, default: Value) -> Result<Value, String> {
    match val {
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            args,
        }
        | Value::EnumField {
            const_idx: 1,
            tag: 0,
            args,
        } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Ok(default)
            }
        }
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            ..
        }
        | Value::EnumField {
            const_idx: 1,
            tag: 1,
            ..
        } => Ok(default),
        other => Ok(other),
    }
}

fn expect_val(val: Value, msg: Value) -> Result<Value, String> {
    let msg_str = match &msg {
        Value::String(s) => s.to_string(),
        _ => format!("{}", msg),
    };
    match val {
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            args,
        }
        | Value::EnumField {
            const_idx: 1,
            tag: 0,
            args,
        } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err(format!("{}: value was empty", msg_str))
            }
        }
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            args,
        } => {
            let err_msg = args
                .first()
                .map(|(_, v)| v.to_string())
                .unwrap_or_else(|| "Error".to_string());
            Err(format!("{}: {}", msg_str, err_msg))
        }
        Value::EnumField {
            const_idx: 1,
            tag: 1,
            ..
        } => Err(format!("{}: None", msg_str)),
        _ => Ok(val),
    }
}

fn unwrap_err_val(val: Value) -> Result<Value, String> {
    match val {
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            args,
        } => {
            if let Some((_, v)) = args.first() {
                Ok(v.clone())
            } else {
                Err("Result::Err had no error content".to_string())
            }
        }
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            args,
        } => {
            let val_str = args
                .first()
                .map(|(_, v)| v.to_string())
                .unwrap_or_else(|| "".to_string());
            Err(format!(
                "called `unwrap_err()` on an `Ok` value: {}",
                val_str
            ))
        }
        _ => Err("called `unwrap_err()` on non-Result value".to_string()),
    }
}

fn option_ok_or(val: Value, err: Value) -> Result<Value, String> {
    match val {
        Value::EnumField {
            const_idx: 1,
            tag: 0,
            args,
        } => {
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
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            args,
        } => {
            if let Some((_, v)) = args.first() {
                Ok(Value::some(v.clone()))
            } else {
                Ok(Value::none())
            }
        }
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            ..
        } => Ok(Value::none()),
        _ => Ok(Value::ok(val)),
    }
}

fn result_to_err(val: Value) -> Result<Value, String> {
    match val {
        Value::EnumField {
            const_idx: 0,
            tag: 1,
            args,
        } => {
            if let Some((_, e)) = args.first() {
                Ok(Value::some(e.clone()))
            } else {
                Ok(Value::none())
            }
        }
        Value::EnumField {
            const_idx: 0,
            tag: 0,
            ..
        } => Ok(Value::none()),
        _ => Ok(Value::err(val)),
    }
}

fn raw_bytes_new(size: Value) -> Result<Value, String> {
    let s = match size {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer for bytes length")),
    };
    Ok(Value::ok(Value::bytes(vec![0u8; s])))
}

fn raw_bytes_from_string(str_val: Value) -> Result<Value, String> {
    match str_val {
        Value::String(s) => Ok(Value::bytes(s.as_bytes().to_vec())),
        _ => Ok(Value::err("Expected string for bytes_from_string")),
    }
}

fn raw_bytes_from_array(arr: Value) -> Result<Value, String> {
    match arr {
        Value::Object(map_ref) => {
            let map = map_ref.borrow();
            let mut vec = Vec::with_capacity(map.len());
            for i in 0..(map.len() as i64) {
                let key = Value::Int(i).get_hash();
                if let Some(val) = map.get(&key) {
                    if let Value::Int(b) = val {
                        vec.push((b & 0xFF) as u8);
                    } else {
                        vec.push(0);
                    }
                }
            }
            Ok(Value::bytes(vec))
        }
        Value::Bytes(b_ref) => Ok(Value::bytes(b_ref.borrow().clone())),
        _ => Ok(Value::err("Expected object array or bytes")),
    }
}

fn raw_bytes_from_hex(hex_val: Value) -> Result<Value, String> {
    let s = match hex_val {
        Value::String(s) => s,
        _ => return Ok(Value::err("Expected string for bytes_from_hex")),
    };
    let clean = s.trim_start_matches("0x").trim_start_matches("0X");
    if clean.len() % 2 != 0 {
        return Ok(Value::err("Hex string must have even length"));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for chunk in clean.as_bytes().chunks(2) {
        let chunk_str = match std::str::from_utf8(chunk) {
            Ok(c) => c,
            Err(_) => return Ok(Value::err("Invalid UTF-8 in hex string")),
        };
        match u8::from_str_radix(chunk_str, 16) {
            Ok(b) => bytes.push(b),
            Err(e) => return Ok(Value::err(format!("Invalid hex character: {}", e))),
        }
    }
    Ok(Value::ok(Value::bytes(bytes)))
}

fn raw_bytes_len(buf: Value) -> Result<Value, String> {
    match buf {
        Value::Bytes(b) => Ok(Value::Int(b.borrow().len() as i64)),
        _ => Err("Expected Bytes for bytes_len".to_string()),
    }
}

fn raw_bytes_get(buf: Value, idx: Value) -> Result<Value, String> {
    let index = match idx {
        Value::Int(i) if i >= 0 => i as usize,
        _ => {
            return Ok(Value::err(
                "Expected non-negative integer index for bytes_get",
            ));
        }
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            if index < slice.len() {
                Ok(Value::ok(Value::Int(slice[index] as i64)))
            } else {
                Ok(Value::err("Index out of bounds"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_set(buf: Value, idx: Value, val: Value) -> Result<Value, String> {
    let index = match idx {
        Value::Int(i) if i >= 0 => i as usize,
        _ => {
            return Ok(Value::err(
                "Expected non-negative integer index for bytes_set",
            ));
        }
    };
    let byte_val = match val {
        Value::Int(i) => (i & 0xFF) as u8,
        _ => return Ok(Value::err("Expected integer byte value")),
    };
    match buf {
        Value::Bytes(b) => {
            let mut slice = b.borrow_mut();
            if index < slice.len() {
                slice[index] = byte_val;
                Ok(Value::ok(Value::Bool(true)))
            } else {
                Ok(Value::err("Index out of bounds"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_push(buf: Value, val: Value) -> Result<Value, String> {
    let byte_val = match val {
        Value::Int(i) => (i & 0xFF) as u8,
        _ => return Err("Expected integer byte for bytes_push".to_string()),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().push(byte_val);
            Ok(Value::Bool(true))
        }
        _ => Err("Expected Bytes for bytes_push".to_string()),
    }
}

fn raw_bytes_extend(buf: Value, other: Value) -> Result<Value, String> {
    match (&buf, &other) {
        (Value::Bytes(b1), Value::Bytes(b2)) => {
            let other_slice = b2.borrow().clone();
            b1.borrow_mut().extend_from_slice(&other_slice);
            Ok(Value::Bool(true))
        }
        (Value::Bytes(b1), Value::String(s)) => {
            b1.borrow_mut().extend_from_slice(s.as_bytes());
            Ok(Value::Bool(true))
        }
        _ => Err("Expected Bytes and Bytes/String for bytes_extend".to_string()),
    }
}

fn raw_bytes_slice(buf: Value, start: Value, end: Value) -> Result<Value, String> {
    let s_idx = match start {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer for slice start")),
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            let e_idx = match end {
                Value::Int(i) if i >= 0 => std::cmp::min(i as usize, slice.len()),
                _ => slice.len(),
            };
            if s_idx <= e_idx && s_idx <= slice.len() {
                Ok(Value::ok(Value::bytes(slice[s_idx..e_idx].to_vec())))
            } else {
                Ok(Value::err("Invalid slice range"))
            }
        }
        _ => Ok(Value::err("Expected Bytes for bytes_slice")),
    }
}

fn raw_bytes_resize(buf: Value, new_len: Value, fill: Value) -> Result<Value, String> {
    let len = match new_len {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Err("Expected non-negative integer for new length".to_string()),
    };
    let fill_byte = match fill {
        Value::Int(i) => (i & 0xFF) as u8,
        _ => 0u8,
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().resize(len, fill_byte);
            Ok(Value::Bool(true))
        }
        _ => Err("Expected Bytes for bytes_resize".to_string()),
    }
}

fn raw_bytes_fill(buf: Value, byte_val: Value) -> Result<Value, String> {
    let b_val = match byte_val {
        Value::Int(i) => (i & 0xFF) as u8,
        _ => return Err("Expected integer byte for bytes_fill".to_string()),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().fill(b_val);
            Ok(Value::Bool(true))
        }
        _ => Err("Expected Bytes for bytes_fill".to_string()),
    }
}

fn raw_bytes_to_string(buf: Value) -> Result<Value, String> {
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            match std::str::from_utf8(&slice) {
                Ok(s) => Ok(Value::ok(Value::String(s.to_string().into()))),
                Err(e) => Ok(Value::err(format!("Invalid UTF-8: {}", e))),
            }
        }
        Value::String(s) => Ok(Value::ok(Value::String(s))),
        other => Ok(Value::ok(Value::String(format!("{}", other).into()))),
    }
}

fn raw_bytes_to_hex(buf: Value) -> Result<Value, String> {
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            let mut hex_str = String::with_capacity(slice.len() * 2);
            for byte in slice.iter() {
                use std::fmt::Write;
                let _ = write!(hex_str, "{:02x}", byte);
            }
            Ok(Value::String(hex_str.into()))
        }
        _ => Err("Expected Bytes for bytes_to_hex".to_string()),
    }
}

fn raw_bytes_get_u16_be(buf: Value, offset: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            if off + 2 <= slice.len() {
                let num = u16::from_be_bytes([slice[off], slice[off + 1]]);
                Ok(Value::ok(Value::Int(num as i64)))
            } else {
                Ok(Value::err("Offset out of bounds for get_u16_be"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_get_u16_le(buf: Value, offset: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            if off + 2 <= slice.len() {
                let num = u16::from_le_bytes([slice[off], slice[off + 1]]);
                Ok(Value::ok(Value::Int(num as i64)))
            } else {
                Ok(Value::err("Offset out of bounds for get_u16_le"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_set_u16_be(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    let num = match val {
        Value::Int(i) => i as u16,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            let mut slice = b.borrow_mut();
            if off + 2 <= slice.len() {
                let bytes = num.to_be_bytes();
                slice[off..off + 2].copy_from_slice(&bytes);
                Ok(Value::ok(Value::Bool(true)))
            } else {
                Ok(Value::err("Offset out of bounds for set_u16_be"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_set_u16_le(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    let num = match val {
        Value::Int(i) => i as u16,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            let mut slice = b.borrow_mut();
            if off + 2 <= slice.len() {
                let bytes = num.to_le_bytes();
                slice[off..off + 2].copy_from_slice(&bytes);
                Ok(Value::ok(Value::Bool(true)))
            } else {
                Ok(Value::err("Offset out of bounds for set_u16_le"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_get_u32_be(buf: Value, offset: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            if off + 4 <= slice.len() {
                let bytes: [u8; 4] = slice[off..off + 4].try_into().unwrap();
                Ok(Value::ok(Value::Int(u32::from_be_bytes(bytes) as i64)))
            } else {
                Ok(Value::err("Offset out of bounds for get_u32_be"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_get_u32_le(buf: Value, offset: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            if off + 4 <= slice.len() {
                let bytes: [u8; 4] = slice[off..off + 4].try_into().unwrap();
                Ok(Value::ok(Value::Int(u32::from_le_bytes(bytes) as i64)))
            } else {
                Ok(Value::err("Offset out of bounds for get_u32_le"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_set_u32_be(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    let num = match val {
        Value::Int(i) => i as u32,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            let mut slice = b.borrow_mut();
            if off + 4 <= slice.len() {
                slice[off..off + 4].copy_from_slice(&num.to_be_bytes());
                Ok(Value::ok(Value::Bool(true)))
            } else {
                Ok(Value::err("Offset out of bounds for set_u32_be"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_set_u32_le(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    let num = match val {
        Value::Int(i) => i as u32,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            let mut slice = b.borrow_mut();
            if off + 4 <= slice.len() {
                slice[off..off + 4].copy_from_slice(&num.to_le_bytes());
                Ok(Value::ok(Value::Bool(true)))
            } else {
                Ok(Value::err("Offset out of bounds for set_u32_le"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_get_u64_be(buf: Value, offset: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            if off + 8 <= slice.len() {
                let bytes: [u8; 8] = slice[off..off + 8].try_into().unwrap();
                Ok(Value::ok(Value::Int(u64::from_be_bytes(bytes) as i64)))
            } else {
                Ok(Value::err("Offset out of bounds for get_u64_be"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_get_u64_le(buf: Value, offset: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    match buf {
        Value::Bytes(b) => {
            let slice = b.borrow();
            if off + 8 <= slice.len() {
                let bytes: [u8; 8] = slice[off..off + 8].try_into().unwrap();
                Ok(Value::ok(Value::Int(u64::from_le_bytes(bytes) as i64)))
            } else {
                Ok(Value::err("Offset out of bounds for get_u64_le"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_set_u64_be(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    let num = match val {
        Value::Int(i) => i as u64,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            let mut slice = b.borrow_mut();
            if off + 8 <= slice.len() {
                slice[off..off + 8].copy_from_slice(&num.to_be_bytes());
                Ok(Value::ok(Value::Bool(true)))
            } else {
                Ok(Value::err("Offset out of bounds for set_u64_be"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_set_u64_le(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
    let off = match offset {
        Value::Int(i) if i >= 0 => i as usize,
        _ => return Ok(Value::err("Expected non-negative integer offset")),
    };
    let num = match val {
        Value::Int(i) => i as u64,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            let mut slice = b.borrow_mut();
            if off + 8 <= slice.len() {
                slice[off..off + 8].copy_from_slice(&num.to_le_bytes());
                Ok(Value::ok(Value::Bool(true)))
            } else {
                Ok(Value::err("Offset out of bounds for set_u64_le"))
            }
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}
fn raw_bytes_append_u8(buf: Value, val: Value) -> Result<Value, String> {
    let num = match val {
        Value::Int(i) => (i & 0xFF) as u8,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().push(num);
            Ok(Value::ok(Value::Bool(true)))
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_append_u16_be(buf: Value, val: Value) -> Result<Value, String> {
    let num = match val {
        Value::Int(i) => i as u16,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().extend_from_slice(&num.to_be_bytes());
            Ok(Value::ok(Value::Bool(true)))
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_append_u16_le(buf: Value, val: Value) -> Result<Value, String> {
    let num = match val {
        Value::Int(i) => i as u16,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().extend_from_slice(&num.to_le_bytes());
            Ok(Value::ok(Value::Bool(true)))
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_append_u32_be(buf: Value, val: Value) -> Result<Value, String> {
    let num = match val {
        Value::Int(i) => i as u32,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().extend_from_slice(&num.to_be_bytes());
            Ok(Value::ok(Value::Bool(true)))
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_append_u32_le(buf: Value, val: Value) -> Result<Value, String> {
    let num = match val {
        Value::Int(i) => i as u32,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().extend_from_slice(&num.to_le_bytes());
            Ok(Value::ok(Value::Bool(true)))
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_append_u64_be(buf: Value, val: Value) -> Result<Value, String> {
    let num = match val {
        Value::Int(i) => i as u64,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().extend_from_slice(&num.to_be_bytes());
            Ok(Value::ok(Value::Bool(true)))
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn raw_bytes_append_u64_le(buf: Value, val: Value) -> Result<Value, String> {
    let num = match val {
        Value::Int(i) => i as u64,
        _ => return Ok(Value::err("Expected integer value")),
    };
    match buf {
        Value::Bytes(b) => {
            b.borrow_mut().extend_from_slice(&num.to_le_bytes());
            Ok(Value::ok(Value::Bool(true)))
        }
        _ => Ok(Value::err("Expected Bytes")),
    }
}

fn compute_sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&len_bits.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let bytes: [u8; 4] = chunk[i * 4..(i + 1) * 4].try_into().unwrap();
            w[i] = u32::from_be_bytes(bytes);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, item) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*item);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() + 2).div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        let i0 = (b0 >> 2) as usize;
        let i1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
        let i2 = (((b1 & 0x0F) << 2) | (b2 >> 6)) as usize;
        let i3 = (b2 & 0x3F) as usize;

        result.push(BASE64_CHARS[i0] as char);
        result.push(BASE64_CHARS[i1] as char);
        if chunk.len() > 1 {
            result.push(BASE64_CHARS[i2] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(BASE64_CHARS[i3] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err("Invalid Base64 length".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let mut indices = [0u8; 4];
        let mut pad_count = 0;
        for i in 0..4 {
            let b = chunk[i];
            if b == b'=' {
                pad_count += 1;
                indices[i] = 0;
            } else if let Some(idx) = BASE64_CHARS.iter().position(|&c| c == b) {
                indices[i] = idx as u8;
            } else {
                return Err(format!("Invalid Base64 character: {}", b as char));
            }
        }
        let b0 = (indices[0] << 2) | (indices[1] >> 4);
        let b1 = ((indices[1] & 0x0F) << 4) | (indices[2] >> 2);
        let b2 = ((indices[2] & 0x03) << 6) | indices[3];

        out.push(b0);
        if pad_count < 2 {
            out.push(b1);
        }
        if pad_count < 1 {
            out.push(b2);
        }
    }
    Ok(out)
}

fn raw_sha1(val: Value) -> Result<Value, String> {
    let bytes = match &val {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Bytes(b) => b.borrow().clone(),
        _ => return Ok(Value::err("Expected String or Bytes for sha1")),
    };
    let hash = compute_sha1(&bytes);
    Ok(Value::ok(Value::bytes(hash.to_vec())))
}


fn raw_base64_encode(val: Value) -> Result<Value, String> {
    let bytes = match &val {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Bytes(b) => b.borrow().clone(),
        _ => return Ok(Value::err("Expected String or Bytes for base64_encode")),
    };
    Ok(Value::String(encode_base64(&bytes).into()))
}


fn raw_base64_decode(val: Value) -> Result<Value, String> {
    let s = match val {
        Value::String(s) => s,
        _ => return Ok(Value::err("Expected String for base64_decode")),
    };
    match decode_base64(&s) {
        Ok(bytes) => Ok(Value::ok(Value::bytes(bytes))),
        Err(e) => Ok(Value::err(Value::String(e.into()))),
    }
}


fn raw_sec_websocket_accept(key: Value) -> Result<Value, String> {
    let k = match key {
        Value::String(s) => s,
        _ => return Ok(Value::err("Expected String for sec_websocket_accept key")),
    };
    let combined = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", k);
    let hash = compute_sha1(combined.as_bytes());
    Ok(Value::String(encode_base64(&hash).into()))
}


pub static EXTRA_NATIVES: std::sync::OnceLock<std::sync::Mutex<Vec<NativeFunction>>> =
    std::sync::OnceLock::new();

pub fn register_extra_native(
    name: &'static str,
    arity: u8,
    call: fn(args: &[Value]) -> Result<Value, String>,
) {
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

fn raw_net_tcp_connect(addr: Value) -> Result<Value, String> {
    let addr_str = match addr {
        Value::String(s) => s.to_string(),
        _ => return Ok(Value::err("Expected string address for tcp_connect")),
    };

    match TcpStream::connect(&addr_str) {
        Ok(stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
            let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
            get_sockets()
                .lock()
                .unwrap()
                .insert(id, SocketStream::Tcp(stream));
            Ok(Value::ok(Value::Int(id as i64)))
        }
        Err(e) => Ok(Value::err(Value::String(
            format!("Failed to connect to {}: {}", addr_str, e).into(),
        ))),
    }
}


fn raw_net_tls_connect(host: Value, port: Value) -> Result<Value, String> {
    let host_str = match host {
        Value::String(s) => s.to_string(),
        _ => return Ok(Value::err("Expected string host for tls_connect")),
    };
    let port_num = match port {
        Value::Int(i) => i as u16,
        _ => 443u16,
    };

    let addr = format!("{}:{}", host_str, port_num);
    let tcp_stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            return Ok(Value::err(Value::String(
                format!("TCP connection to {} failed: {}", addr, e).into(),
            )));
        }
    };

    let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp_stream.set_write_timeout(Some(Duration::from_secs(10)));

    let connector = match native_tls::TlsConnector::new() {
        Ok(c) => c,
        Err(e) => {
            return Ok(Value::err(Value::String(
                format!("Failed to initialize TLS connector: {}", e).into(),
            )));
        }
    };

    match connector.connect(&host_str, tcp_stream) {
        Ok(tls_stream) => {
            let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
            get_sockets()
                .lock()
                .unwrap()
                .insert(id, SocketStream::Tls(tls_stream));
            Ok(Value::ok(Value::Int(id as i64)))
        }
        Err(e) => Ok(Value::err(Value::String(
            format!("TLS handshake with {} failed: {}", host_str, e).into(),
        ))),
    }
}


fn raw_net_unix_connect(path: Value) -> Result<Value, String> {
    let path_str = match path {
        Value::String(s) => s.to_string(),
        _ => return Ok(Value::err("Expected string path for unix_connect")),
    };

    match UnixStream::connect(&path_str) {
        Ok(stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
            let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
            get_sockets()
                .lock()
                .unwrap()
                .insert(id, SocketStream::Unix(stream));
            Ok(Value::ok(Value::Int(id as i64)))
        }
        Err(e) => Ok(Value::err(Value::String(
            format!("Failed to connect to UNIX socket {}: {}", path_str, e).into(),
        ))),
    }
}

fn raw_net_read(socket_id: Value, max_len: Value) -> Result<Value, String> {
    let id = match socket_id {
        Value::Int(i) if i > 0 => i as u64,
        _ => return Ok(Value::err("Expected integer socket id for net_read")),
    };
    let len = match max_len {
        Value::Int(i) if i > 0 => i as usize,
        _ => 4096usize,
    };

    let mut sockets = get_sockets().lock().unwrap();
    let stream = match sockets.get_mut(&id) {
        Some(s) => s,
        None => return Ok(Value::err("Socket not found or already closed")),
    };

    let mut buf = vec![0u8; len];
    let read_res = match stream {
        SocketStream::Tcp(s) => s.read(&mut buf),
        SocketStream::Tls(s) => s.read(&mut buf),
        SocketStream::Unix(s) => s.read(&mut buf),
    };

    match read_res {
        Ok(n) => {
            buf.truncate(n);
            Ok(Value::ok(Value::bytes(buf)))
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Ok(Value::err(Value::String("WouldBlock".to_string().into())))
            } else if e.kind() == std::io::ErrorKind::TimedOut {
                Ok(Value::err(Value::String("TimedOut".to_string().into())))
            } else {
                Ok(Value::err(Value::String(
                    format!("Read error: {}", e).into(),
                )))
            }
        }
    }
}


fn raw_net_write(socket_id: Value, data: Value) -> Result<Value, String> {
    let id = match socket_id {
        Value::Int(i) if i > 0 => i as u64,
        _ => return Ok(Value::err("Expected integer socket id for net_write")),
    };

    let bytes = match &data {
        Value::Bytes(b) => b.borrow().clone(),
        Value::String(s) => s.as_bytes().to_vec(),
        _ => return Ok(Value::err("Expected Bytes or String data for net_write")),
    };

    let mut sockets = get_sockets().lock().unwrap();
    let stream = match sockets.get_mut(&id) {
        Some(s) => s,
        None => return Ok(Value::err("Socket not found or already closed")),
    };

    let write_res = match stream {
        SocketStream::Tcp(s) => s.write_all(&bytes).and_then(|_| s.flush()),
        SocketStream::Tls(s) => s.write_all(&bytes).and_then(|_| s.flush()),
        SocketStream::Unix(s) => s.write_all(&bytes).and_then(|_| s.flush()),
    };

    match write_res {
        Ok(()) => Ok(Value::ok(Value::Int(bytes.len() as i64))),
        Err(e) => Ok(Value::err(Value::String(
            format!("Write error: {}", e).into(),
        ))),
    }
}


fn raw_net_close(socket_id: Value) -> Result<Value, String> {
    let id = match socket_id {
        Value::Int(i) if i > 0 => i as u64,
        _ => return Ok(Value::err("Expected integer socket id for net_close")),
    };

    let mut sockets = get_sockets().lock().unwrap();
    if let Some(stream) = sockets.remove(&id) {
        match stream {
            SocketStream::Tcp(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            SocketStream::Tls(mut s) => {
                let _ = s.shutdown();
            }
            SocketStream::Unix(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
        Ok(Value::ok(Value::Bool(true)))
    } else {
        Ok(Value::ok(Value::Bool(false)))
    }
}


fn raw_net_set_timeout(socket_id: Value, timeout_ms: Value) -> Result<Value, String> {
    let id = match socket_id {
        Value::Int(i) if i > 0 => i as u64,
        _ => return Ok(Value::err("Expected integer socket id for net_set_timeout")),
    };
    let ms = match timeout_ms {
        Value::Int(i) if i >= 0 => i as u64,
        _ => return Ok(Value::err("Expected non-negative integer for timeout_ms")),
    };
    let timeout = if ms == 0 {
        None
    } else {
        Some(Duration::from_millis(ms))
    };

    let sockets = get_sockets().lock().unwrap();
    if let Some(stream) = sockets.get(&id) {
        match stream {
            SocketStream::Tcp(s) => {
                let _ = s.set_read_timeout(timeout);
                let _ = s.set_write_timeout(timeout);
            }
            SocketStream::Tls(s) => {
                let _ = s.get_ref().set_read_timeout(timeout);
                let _ = s.get_ref().set_write_timeout(timeout);
            }
            SocketStream::Unix(s) => {
                let _ = s.set_read_timeout(timeout);
                let _ = s.set_write_timeout(timeout);
            }
        }
        Ok(Value::ok(Value::Bool(true)))
    } else {
        Ok(Value::err("Socket not found or already closed"))
    }
}


fn raw_net_set_nonblocking(socket_id: Value, nonblocking: Value) -> Result<Value, String> {
    let id = match socket_id {
        Value::Int(i) if i > 0 => i as u64,
        _ => {
            return Ok(Value::err(
                "Expected integer socket id for net_set_nonblocking",
            ));
        }
    };
    let nb = match nonblocking {
        Value::Bool(b) => b,
        _ => return Ok(Value::err("Expected boolean for nonblocking")),
    };

    let sockets = get_sockets().lock().unwrap();
    if let Some(stream) = sockets.get(&id) {
        let res = match stream {
            SocketStream::Tcp(s) => s.set_nonblocking(nb),
            SocketStream::Tls(s) => s.get_ref().set_nonblocking(nb),
            SocketStream::Unix(s) => s.set_nonblocking(nb),
        };
        match res {
            Ok(()) => Ok(Value::ok(Value::Bool(true))),
            Err(e) => Ok(Value::err(Value::String(
                format!("set_nonblocking error: {}", e).into(),
            ))),
        }
    } else {
        Ok(Value::err("Socket not found or already closed"))
    }
}


fn raw_sleep(ms_val: Value) -> Result<Value, String> {
    let ms = match ms_val {
        Value::Int(i) if i >= 0 => i as u64,
        _ => {
            return Ok(Value::err(
                "Expected non-negative integer milliseconds for sleep",
            ));
        }
    };
    std::thread::sleep(Duration::from_millis(ms));
    Ok(Value::ok(Value::Bool(true)))
}

#[parts_std(overlays = [("std.math", "std/math.pts"), ("std.bytes", "std/bytes.pts"), ("std.ws", "std/ws.pts")])]
pub mod builtins {
    use super::*;

    #[std_const(module = "std.math", export = "PI")]
    pub const PI: f64 = std::f64::consts::PI;

    #[native_function]
    pub fn println(args: &[Value]) -> Result<Value, String> {
        raw_println(args)
    }

    #[native_function]
    pub fn print(args: &[Value]) -> Result<Value, String> {
        raw_print(args)
    }

    #[native_function(module = "std.sys", export = "time", globals = ["__timestamp"])]
    pub fn __timestamp() -> Result<Value, String> {
        raw_timestamp()
    }

    #[native_function]
    pub fn __iter_of(val: Value) -> Result<Value, String> {
        raw_iter_of(val)
    }

    #[native_function]
    pub fn __get_next(obj: Value) -> Result<Value, String> {
        raw_get_next(obj)
    }

    #[native_function]
    pub fn __has_next(obj: Value) -> Result<Value, String> {
        raw_has_next(obj)
    }

    #[native_function(module = "std.math", export = "rand", globals = ["__rand"])]
    pub fn __rand() -> Result<Value, String> {
        raw_rand()
    }

    #[native_function(arity = 1, module = "std.sys", export = "exec", globals = ["__exec"])]
    pub fn __exec(args: &[Value]) -> Result<Value, String> {
        raw_exec(args)
    }

    #[native_function(module = "std.sys", export = "env", globals = ["__env"])]
    pub fn __env(name: Value) -> Result<Value, String> {
        raw_env(name)
    }

    #[native_function(module = "std.str", export = "join", globals = ["__joinStr", "join"])]
    pub fn __joinStr(arg_one: Value, arg_two: Value) -> Result<Value, String> {
        raw_join_str(arg_one, arg_two)
    }

    #[native_function(module = "std.math", export = "sin", globals = ["__math_sin"])]
    pub fn __math_sin(val: Value) -> Result<Value, String> {
        raw_math_sin(val)
    }

    #[native_function(module = "std.math", export = "cos", globals = ["__math_cos"])]
    pub fn __math_cos(val: Value) -> Result<Value, String> {
        raw_math_cos(val)
    }

    #[native_function(module = "std.math", export = "floor", globals = ["__math_floor"])]
    pub fn __math_floor(val: Value) -> Result<Value, String> {
        raw_math_floor(val)
    }

    #[native_function(module = "std.math", export = "pow", globals = ["__math_pow"])]
    pub fn __math_pow(exp: Value, pow: Value) -> Result<Value, String> {
        raw_math_pow(exp, pow)
    }

    #[native_function(module = "std.str", export = "len", globals = ["__str_len"])]
    pub fn __str_len(val: Value) -> Result<Value, String> {
        raw_str_len(val)
    }

    #[native_function(module = "std.str", export = "strip_prefix", globals = ["__str_strip_prefix", "strip_prefix"])]
    pub fn __str_strip_prefix(str: Value, prefix: Value) -> Result<Value, String> {
        raw_str_strip_prefix(str, prefix)
    }

    #[native_function(module = "std.str", export = "strip_suffix", globals = ["__str_strip_suffix", "strip_suffix"])]
    pub fn __str_strip_suffix(str: Value, suffix: Value) -> Result<Value, String> {
        raw_str_strip_suffix(str, suffix)
    }

    #[native_function(module = "std.str", export = "lower", globals = ["__str_lower", "lower"])]
    pub fn __str_lower(val: Value) -> Result<Value, String> {
        raw_str_lower(val)
    }

    #[native_function(module = "std.str", export = "upper", globals = ["__str_upper", "upper"])]
    pub fn __str_upper(val: Value) -> Result<Value, String> {
        raw_str_upper(val)
    }

    #[native_function(module = "std.str", export = "byte_at", globals = ["__str_byte_at", "byte_at"])]
    pub fn __str_byte_at(str: Value, idx: Value) -> Result<Value, String> {
        raw_str_byte_at(str, idx)
    }

    #[native_function(module = "std", export = "rotate_left", globals = ["__byte_rotate_left"])]
    pub fn __byte_rotate_left(left: Value, right: Value, mask: Value) -> Result<Value, String> {
        raw_byte_rotate_left(left, right, mask)
    }

    #[native_function(module = "std", export = "len", globals = ["__object_len", "len"])]
    pub fn __object_len(obj: Value) -> Result<Value, String> {
        raw_object_len(obj)
    }

    #[native_function(modules = ["std", "std.result"], export = "is_ok", globals = ["__result_is_ok", "is_ok"])]
    pub fn __result_is_ok(val: Value) -> Result<Value, String> {
        result_is_ok(val)
    }

    #[native_function(modules = ["std", "std.result"], export = "is_err", globals = ["__result_is_err", "is_err"])]
    pub fn __result_is_err(val: Value) -> Result<Value, String> {
        result_is_err(val)
    }

    #[native_function(modules = ["std", "std.option"], export = "is_some", globals = ["__option_is_some", "is_some"])]
    pub fn __option_is_some(val: Value) -> Result<Value, String> {
        option_is_some(val)
    }

    #[native_function(modules = ["std", "std.option"], export = "is_none", globals = ["__option_is_none", "is_none"])]
    pub fn __option_is_none(val: Value) -> Result<Value, String> {
        option_is_none(val)
    }

    #[native_function(modules = ["std", "std.result", "std.option"], export = "unwrap", globals = ["__result_unwrap", "unwrap"])]
    pub fn __result_unwrap(val: Value) -> Result<Value, String> {
        unwrap_val(val)
    }

    #[native_function(modules = ["std", "std.result", "std.option"], export = "unwrap_or", globals = ["__result_unwrap_or", "unwrap_or"])]
    pub fn __result_unwrap_or(val: Value, default: Value) -> Result<Value, String> {
        unwrap_or_val(val, default)
    }

    #[native_function(modules = ["std", "std.result", "std.option"], export = "expect", globals = ["__result_expect", "expect"])]
    pub fn __result_expect(val: Value, msg: Value) -> Result<Value, String> {
        expect_val(val, msg)
    }

    #[native_function(modules = ["std", "std.result"], export = "unwrap_err", globals = ["__result_unwrap_err", "unwrap_err"])]
    pub fn __result_unwrap_err(val: Value) -> Result<Value, String> {
        unwrap_err_val(val)
    }

    #[native_function(modules = ["std", "std.option"], export = "ok_or", globals = ["__option_ok_or", "ok_or"])]
    pub fn __option_ok_or(val: Value, err: Value) -> Result<Value, String> {
        option_ok_or(val, err)
    }

    #[native_function(exports = ["std.Ok", "std.result.ok", "std.result.Ok"], globals = ["__result_ok", "ok"])]
    pub fn __result_ok(val: Value) -> Result<Value, String> {
        result_to_ok(val)
    }

    #[native_function(exports = ["std.Err", "std.result.err", "std.result.Err"], globals = ["__result_err", "err"])]
    pub fn __result_err(err: Value) -> Result<Value, String> {
        result_to_err(err)
    }

    #[native_function(exports = ["std.Some", "std.option.some", "std.option.Some"], globals = ["__option_some", "some"])]
    pub fn __option_some(val: Value) -> Result<Value, String> {
        Ok(Value::some(val))
    }

    #[native_function(exports = ["std.None", "std.option.none", "std.option.None"], globals = ["__option_none", "none"])]
    pub fn __option_none() -> Result<Value, String> {
        Ok(Value::none())
    }

    #[native_function(module = "std.bytes", export = "new", globals = ["__bytes_new", "bytes_new", "bytes"])]
    pub fn __bytes_new(size: Value) -> Result<Value, String> {
        raw_bytes_new(size)
    }

    #[native_function(module = "std.bytes", export = "from_string", globals = ["__bytes_from_string"])]
    pub fn __bytes_from_string(str_val: Value) -> Result<Value, String> {
        raw_bytes_from_string(str_val)
    }

    #[native_function(module = "std.bytes", export = "from_array", globals = ["__bytes_from_array"])]
    pub fn __bytes_from_array(arr: Value) -> Result<Value, String> {
        raw_bytes_from_array(arr)
    }

    #[native_function(module = "std.bytes", export = "from_hex", globals = ["__bytes_from_hex"])]
    pub fn __bytes_from_hex(hex_val: Value) -> Result<Value, String> {
        raw_bytes_from_hex(hex_val)
    }

    #[native_function(module = "std.bytes", export = "len", globals = ["__bytes_len", "bytes_len"])]
    pub fn __bytes_len(buf: Value) -> Result<Value, String> {
        raw_bytes_len(buf)
    }

    #[native_function(exports = ["std.bytes.get", "std.bytes.get_u8"], globals = ["__bytes_get", "__bytes_get_u8", "bytes_get", "get", "get_u8"])]
    pub fn __bytes_get(buf: Value, idx: Value) -> Result<Value, String> {
        raw_bytes_get(buf, idx)
    }

    #[native_function(exports = ["std.bytes.set", "std.bytes.set_u8"], globals = ["__bytes_set", "__bytes_set_u8", "bytes_set", "set", "set_u8"])]
    pub fn __bytes_set(buf: Value, idx: Value, val: Value) -> Result<Value, String> {
        raw_bytes_set(buf, idx, val)
    }

    #[native_function(module = "std.bytes", export = "push", globals = ["__bytes_push", "bytes_push", "push"])]
    pub fn __bytes_push(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_push(buf, val)
    }

    #[native_function(module = "std.bytes", export = "extend", globals = ["__bytes_extend", "bytes_extend", "extend"])]
    pub fn __bytes_extend(buf: Value, other: Value) -> Result<Value, String> {
        raw_bytes_extend(buf, other)
    }

    #[native_function(module = "std.bytes", export = "slice", globals = ["__bytes_slice", "bytes_slice", "slice"])]
    pub fn __bytes_slice(buf: Value, start: Value, end: Value) -> Result<Value, String> {
        raw_bytes_slice(buf, start, end)
    }

    #[native_function(module = "std.bytes", export = "resize", globals = ["__bytes_resize", "bytes_resize", "resize"])]
    pub fn __bytes_resize(buf: Value, new_len: Value, fill: Value) -> Result<Value, String> {
        raw_bytes_resize(buf, new_len, fill)
    }

    #[native_function(module = "std.bytes", export = "fill", globals = ["__bytes_fill", "bytes_fill", "fill"])]
    pub fn __bytes_fill(buf: Value, byte_val: Value) -> Result<Value, String> {
        raw_bytes_fill(buf, byte_val)
    }

    #[native_function(module = "std.bytes", export = "to_string", globals = ["__bytes_to_string", "bytes_to_string", "to_string"])]
    pub fn __bytes_to_string(buf: Value) -> Result<Value, String> {
        raw_bytes_to_string(buf)
    }

    #[native_function(module = "std.bytes", export = "to_hex", globals = ["__bytes_to_hex", "bytes_to_hex", "to_hex"])]
    pub fn __bytes_to_hex(buf: Value) -> Result<Value, String> {
        raw_bytes_to_hex(buf)
    }

    #[native_function(module = "std.bytes", export = "get_u16_be", globals = ["__bytes_get_u16_be", "get_u16_be"])]
    pub fn __bytes_get_u16_be(buf: Value, offset: Value) -> Result<Value, String> {
        raw_bytes_get_u16_be(buf, offset)
    }

    #[native_function(module = "std.bytes", export = "get_u16_le", globals = ["__bytes_get_u16_le", "get_u16_le"])]
    pub fn __bytes_get_u16_le(buf: Value, offset: Value) -> Result<Value, String> {
        raw_bytes_get_u16_le(buf, offset)
    }

    #[native_function(module = "std.bytes", export = "set_u16_be", globals = ["__bytes_set_u16_be", "set_u16_be"])]
    pub fn __bytes_set_u16_be(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
        raw_bytes_set_u16_be(buf, offset, val)
    }

    #[native_function(module = "std.bytes", export = "set_u16_le", globals = ["__bytes_set_u16_le", "set_u16_le"])]
    pub fn __bytes_set_u16_le(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
        raw_bytes_set_u16_le(buf, offset, val)
    }

    #[native_function(module = "std.bytes", export = "get_u32_be", globals = ["__bytes_get_u32_be", "get_u32_be"])]
    pub fn __bytes_get_u32_be(buf: Value, offset: Value) -> Result<Value, String> {
        raw_bytes_get_u32_be(buf, offset)
    }

    #[native_function(module = "std.bytes", export = "get_u32_le", globals = ["__bytes_get_u32_le", "get_u32_le"])]
    pub fn __bytes_get_u32_le(buf: Value, offset: Value) -> Result<Value, String> {
        raw_bytes_get_u32_le(buf, offset)
    }

    #[native_function(module = "std.bytes", export = "set_u32_be", globals = ["__bytes_set_u32_be", "set_u32_be"])]
    pub fn __bytes_set_u32_be(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
        raw_bytes_set_u32_be(buf, offset, val)
    }

    #[native_function(module = "std.bytes", export = "set_u32_le", globals = ["__bytes_set_u32_le", "set_u32_le"])]
    pub fn __bytes_set_u32_le(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
        raw_bytes_set_u32_le(buf, offset, val)
    }

    #[native_function(module = "std.bytes", export = "get_u64_be", globals = ["__bytes_get_u64_be", "get_u64_be"])]
    pub fn __bytes_get_u64_be(buf: Value, offset: Value) -> Result<Value, String> {
        raw_bytes_get_u64_be(buf, offset)
    }

    #[native_function(module = "std.bytes", export = "get_u64_le", globals = ["__bytes_get_u64_le", "get_u64_le"])]
    pub fn __bytes_get_u64_le(buf: Value, offset: Value) -> Result<Value, String> {
        raw_bytes_get_u64_le(buf, offset)
    }

    #[native_function(module = "std.bytes", export = "set_u64_be", globals = ["__bytes_set_u64_be", "set_u64_be"])]
    pub fn __bytes_set_u64_be(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
        raw_bytes_set_u64_be(buf, offset, val)
    }

    #[native_function(module = "std.bytes", export = "set_u64_le", globals = ["__bytes_set_u64_le", "set_u64_le"])]
    pub fn __bytes_set_u64_le(buf: Value, offset: Value, val: Value) -> Result<Value, String> {
        raw_bytes_set_u64_le(buf, offset, val)
    }

    #[native_function(module = "std.bytes", export = "append_u8", globals = ["__bytes_append_u8", "append_u8"])]
    pub fn __bytes_append_u8(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_append_u8(buf, val)
    }

    #[native_function(module = "std.bytes", export = "append_u16_be", globals = ["__bytes_append_u16_be", "append_u16_be"])]
    pub fn __bytes_append_u16_be(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_append_u16_be(buf, val)
    }

    #[native_function(module = "std.bytes", export = "append_u16_le", globals = ["__bytes_append_u16_le", "append_u16_le"])]
    pub fn __bytes_append_u16_le(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_append_u16_le(buf, val)
    }

    #[native_function(module = "std.bytes", export = "append_u32_be", globals = ["__bytes_append_u32_be", "append_u32_be"])]
    pub fn __bytes_append_u32_be(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_append_u32_be(buf, val)
    }

    #[native_function(module = "std.bytes", export = "append_u32_le", globals = ["__bytes_append_u32_le", "append_u32_le"])]
    pub fn __bytes_append_u32_le(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_append_u32_le(buf, val)
    }

    #[native_function(module = "std.bytes", export = "append_u64_be", globals = ["__bytes_append_u64_be", "append_u64_be"])]
    pub fn __bytes_append_u64_be(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_append_u64_be(buf, val)
    }

    #[native_function(module = "std.bytes", export = "append_u64_le", globals = ["__bytes_append_u64_le", "append_u64_le"])]
    pub fn __bytes_append_u64_le(buf: Value, val: Value) -> Result<Value, String> {
        raw_bytes_append_u64_le(buf, val)
    }

    #[native_function(globals = ["__sha1", "sha1"])]
    pub fn __sha1(val: Value) -> Result<Value, String> {
        raw_sha1(val)
    }

    #[native_function(globals = ["__base64_encode", "base64_encode"])]
    pub fn __base64_encode(val: Value) -> Result<Value, String> {
        raw_base64_encode(val)
    }

    #[native_function(globals = ["__base64_decode", "base64_decode"])]
    pub fn __base64_decode(val: Value) -> Result<Value, String> {
        raw_base64_decode(val)
    }

    #[native_function(globals = ["__sec_websocket_accept", "sec_websocket_accept"])]
    pub fn __sec_websocket_accept(key: Value) -> Result<Value, String> {
        raw_sec_websocket_accept(key)
    }

    #[native_function(exports = ["std.tcp_connect", "std.net.tcp_connect"], globals = ["__net_tcp_connect", "tcp_connect"])]
    pub fn __net_tcp_connect(addr: Value) -> Result<Value, String> {
        raw_net_tcp_connect(addr)
    }

    #[native_function(exports = ["std.tls_connect", "std.net.tls_connect"], globals = ["__net_tls_connect", "tls_connect"])]
    pub fn __net_tls_connect(host: Value, port: Value) -> Result<Value, String> {
        raw_net_tls_connect(host, port)
    }

    #[native_function(exports = ["std.unix_connect", "std.net.unix_connect"], globals = ["__net_unix_connect"])]
    pub fn __net_unix_connect(path: Value) -> Result<Value, String> {
        raw_net_unix_connect(path)
    }

    #[native_function(exports = ["std.net_read", "std.net.read"], globals = ["__net_read", "net_read", "read"])]
    pub fn __net_read(socket_id: Value, max_len: Value) -> Result<Value, String> {
        raw_net_read(socket_id, max_len)
    }

    #[native_function(exports = ["std.net_write", "std.net.write"], globals = ["__net_write", "net_write", "write"])]
    pub fn __net_write(socket_id: Value, data: Value) -> Result<Value, String> {
        raw_net_write(socket_id, data)
    }

    #[native_function(exports = ["std.net_close", "std.net.close"], globals = ["__net_close", "net_close", "close"])]
    pub fn __net_close(socket_id: Value) -> Result<Value, String> {
        raw_net_close(socket_id)
    }

    #[native_function(exports = ["std.net_set_timeout", "std.net.set_timeout"], globals = ["__net_set_timeout", "net_set_timeout", "set_timeout"])]
    pub fn __net_set_timeout(socket_id: Value, timeout_ms: Value) -> Result<Value, String> {
        raw_net_set_timeout(socket_id, timeout_ms)
    }

    #[native_function(exports = ["std.net_set_nonblocking", "std.net.set_nonblocking"], globals = ["__net_set_nonblocking", "net_set_nonblocking", "set_nonblocking"])]
    pub fn __net_set_nonblocking(socket_id: Value, nonblocking: Value) -> Result<Value, String> {
        raw_net_set_nonblocking(socket_id, nonblocking)
    }

    #[native_function(exports = ["std.sleep", "std.sys.sleep"], globals = ["__sleep", "sleep"])]
    pub fn __sleep(ms_val: Value) -> Result<Value, String> {
        raw_sleep(ms_val)
    }
}

pub use builtins::*;

#[inline]
pub fn hash_str(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

#[derive(Clone, Debug)]
pub enum StdConstValue {
    Int(i64),
    Double(f64),
    Bool(bool),
    Str(&'static str),
}

impl StdConstValue {
    pub fn to_value(&self) -> Value {
        match self {
            StdConstValue::Int(i) => Value::Int(*i),
            StdConstValue::Double(d) => Value::Double(*d),
            StdConstValue::Bool(b) => Value::Bool(*b),
            StdConstValue::Str(s) => Value::String(Rc::new((*s).to_string())),
        }
    }
}

#[derive(Default, Clone)]
pub struct StdModuleSpec {
    pub submodules: FxHashMap<&'static str, &'static str>,
    pub natives: FxHashMap<&'static str, NativeFunction>,
    pub constants: FxHashMap<&'static str, StdConstValue>,
    pub overlay_asset: Option<&'static str>,
}

#[derive(Default, Clone)]
pub struct StdRegistry {
    pub modules: FxHashMap<&'static str, StdModuleSpec>,
}

impl StdRegistry {
    fn ensure_module(&mut self, mod_path: &'static str) {
        if !self.modules.contains_key(mod_path) {
            self.modules.insert(mod_path, StdModuleSpec::default());
        }
        if let Some((parent, child)) = mod_path.rsplit_once('.') {
            self.ensure_module(parent);
            self.modules
                .get_mut(parent)
                .unwrap()
                .submodules
                .insert(child, mod_path);
        }
    }

    pub fn insert_native(
        &mut self,
        mod_path: &'static str,
        export_name: &'static str,
        func: NativeFunction,
    ) {
        self.ensure_module(mod_path);
        self.modules
            .get_mut(mod_path)
            .unwrap()
            .natives
            .insert(export_name, func);
    }

    pub fn insert_const(
        &mut self,
        mod_path: &'static str,
        export_name: &'static str,
        val: StdConstValue,
    ) {
        self.ensure_module(mod_path);
        self.modules
            .get_mut(mod_path)
            .unwrap()
            .constants
            .insert(export_name, val);
    }

    pub fn set_overlay(&mut self, mod_path: &'static str, asset_path: &'static str) {
        self.ensure_module(mod_path);
        self.modules.get_mut(mod_path).unwrap().overlay_asset = Some(asset_path);
    }

    pub fn resolve_import(&self, source: &str) -> Option<&'static str> {
        let rest = source.strip_prefix("@std")?.trim_start_matches('/');
        if rest.is_empty() || rest == "std.pts" {
            return self.modules.get_key_value("std").map(|(k, _)| *k);
        }
        let no_prefix = rest.strip_prefix("std/").unwrap_or(rest);
        let clean = no_prefix.strip_suffix(".pts").unwrap_or(no_prefix);
        let candidate = if clean == "std" {
            "std".to_string()
        } else {
            format!("std.{}", clean.replace('/', "."))
        };
        self.modules.get_key_value(candidate.as_str()).map(|(k, _)| *k)
    }
}

#[derive(Clone)]
pub struct StdModule {
    pub functions: Vec<NativeFunction>,
}

static STD_DATA: LazyLock<(Vec<NativeFunction>, Vec<NativeFunction>, StdRegistry)> =
    LazyLock::new(builtins::build_std_data);

static CORE_NATIVE_MAP: LazyLock<FxHashMap<u64, NativeFunction>> = LazyLock::new(|| {
    let mut map = FxHashMap::default();
    for f in &STD_DATA.1 {
        map.insert(hash_str(f.name), f.clone());
    }
    map
});

static CORE_GLOBAL_MAP: LazyLock<FxHashMap<&'static str, NativeFunction>> = LazyLock::new(|| {
    let mut map = FxHashMap::default();
    for f in &STD_DATA.0 {
        map.insert(f.name, f.clone());
    }
    map
});

static CORE_ALL_BY_BYTES: LazyLock<FxHashMap<&'static [u8], NativeFunction>> = LazyLock::new(|| {
    let mut map = FxHashMap::default();
    for f in &STD_DATA.1 {
        map.insert(f.name.as_bytes(), f.clone());
    }
    map
});

pub fn std_registry() -> &'static StdRegistry {
    &STD_DATA.2
}

pub fn core_native_map() -> &'static FxHashMap<u64, NativeFunction> {
    &CORE_NATIVE_MAP
}

pub fn core_global_by_name(name: &str) -> Option<&'static NativeFunction> {
    CORE_GLOBAL_MAP.get(name)
}

pub fn core_any_by_bytes(name_bytes: &[u8]) -> Option<&'static NativeFunction> {
    CORE_ALL_BY_BYTES.get(name_bytes)
}

pub fn extra_natives_snapshot() -> Vec<NativeFunction> {
    if let Some(extra) = EXTRA_NATIVES.get()
        && let Ok(guard) = extra.lock()
    {
        return guard.clone();
    }
    Vec::new()
}

pub fn build_std_module_object(
    mod_path: &str,
    overlays: &FxHashMap<String, Value>,
    cache: &mut FxHashMap<String, Value>,
    eval_overlay: &mut impl FnMut(&Value) -> Result<Value, String>,
) -> Result<Value, String> {
    if let Some(existing) = cache.get(mod_path) {
        return Ok(existing.clone());
    }
    let reg = std_registry();
    let spec = reg
        .modules
        .get(mod_path)
        .ok_or_else(|| format!("Unknown std module '{}'", mod_path))?;

    let mut map = FxHashMap::default();
    for (name, val) in &spec.constants {
        map.insert(hash_str(name), val.to_value());
    }
    for (name, func) in &spec.natives {
        map.insert(hash_str(name), Value::NativeFun(func.clone()));
    }
    for (sub_name, sub_path) in &spec.submodules {
        let sub_val = build_std_module_object(sub_path, overlays, cache, eval_overlay)?;
        map.insert(hash_str(sub_name), sub_val);
    }
    if let Some(overlay_fun) = overlays.get(mod_path) {
        let overlay_val = eval_overlay(overlay_fun)?;
        if let Value::Object(obj_ref) = overlay_val {
            for (k, v) in obj_ref.borrow().iter() {
                map.insert(*k, v.clone());
            }
        }
    }
    let obj = Value::Object(Rc::new(RefCell::new(map)));
    cache.insert(mod_path.to_string(), obj.clone());
    Ok(obj)
}

impl StdModule {
    pub fn get_core() -> Self {
        let mut functions = STD_DATA.0.clone();
        if let Some(extra) = EXTRA_NATIVES.get()
            && let Ok(guard) = extra.lock()
        {
            functions.extend((*guard).clone());
        }

        Self { functions }
    }
}
