use std::{
    cell::RefCell,
    collections::HashMap,
    process::Command,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::compiler::{NativeFunction, Value};

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
                    name: "print",
                    arity: 1,
                    call: |args| {
                        for arg in args {
                            print!("{}", arg)
                        }

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
                //The 'naive' PRNG to not use external libs
                NativeFunction {
                    name: "rand",
                    arity: 0,
                    call: |_| {
                        let a = 1103515245;
                        let c = 12345;
                        let m = 2147483648;

                        let seed_source = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_micros();

                        return Ok(Value::Int(((a * seed_source) + c % m) as i64));
                    },
                },
                NativeFunction {
                    name: "exec",
                    arity: 1,
                    call: |args| {
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

                        return if res.is_err() {
                            Ok(Value::Int(1))
                        } else {
                            let output = res.unwrap();

                            let s = String::from_utf8_lossy(&output.stdout);

                            Ok(Value::String(s.to_string()))
                        };
                    },
                },
                NativeFunction {
                    name: "env",
                    arity: 1,
                    call: |args| {
                        let name = match &args[0] {
                            Value::String(s) => s,
                            _ => return Err("Expected string lol".to_string()),
                        };

                        return match std::env::var(name) {
                            Ok(val) => Ok(Value::String(val)),
                            Err(_) => Err("Some error lol".to_string()),
                        };
                    },
                },
            ],
        }
    }
}
