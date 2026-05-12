use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use crate::define_opcodes;
use crate::parser::Ast;
use crate::parser::ImportType;
use crate::parser::Parser;
use crate::parser::Value as ParserValue;
use crate::value::{NativeFunctionDef, StdDefinition, Value};

#[derive(Clone, Debug)]
pub struct Error {
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub level: ErrorLevel,
}

#[derive(Clone, Debug)]
pub enum ErrorLevel {
    Error,
    Warning,
}

define_opcodes! {
    // Constants
    ConstInt    = 0x00,
    ConstDouble = 0x01,
    ConstBool   = 0x02,
    ConstString = 0x03,
    ConstRef    = 0x04,
    ConstFun    = 0x05,
    ConstObj    = 0x06,
    ConstReg    = 0x07,
    ConstAst    = 0x08,
    ConstParserValue = 0x09,

    // Flow Control
    Return      = 0x10,
    Call        = 0x11,
    Binary      = 0x12,
    Jump        = 0x13,
    JumpBy      = 0x14,
    JumpIf      = 0x15,
    JumpNot     = 0x16,
    JumpBack    = 0x17,

    //Register movements
    Load        = 0x20,
    GetProperty = 0x21,
    SetProperty = 0x22,
    LoadNative  = 0x23
}

struct LoopContext {
    target: usize,
    jump_list: Vec<usize>,
}

struct Context {
    bytecode: Vec<u8>,

    scopes: Vec<HashMap<String, u8>>,
    top_level_names: HashMap<String, u8>,
    next_free_register: u8,

    loop_stack: Vec<LoopContext>,

    loaded_natives: HashMap<String, u8>,
}

impl Context {
    fn new() -> Self {
        return Self {
            bytecode: vec![],
            scopes: vec![HashMap::new()],
            top_level_names: HashMap::new(),
            next_free_register: 0,
            loop_stack: vec![],
            loaded_natives: HashMap::new(),
        };
    }

    fn resolve_local(&mut self, name: &str) -> Option<u8> {
        for scope in self.scopes.iter().rev() {
            if let Some(&reg) = scope.get(name) {
                return Some(reg);
            }
        }

        None
    }

    fn begin_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn end_scope(&mut self) {
        if let Some(last_scope) = self.scopes.pop() {
            if let Some(&min_reg) = last_scope.values().min() {
                self.next_free_register = min_reg;
            }
        }
    }

    fn add_local(&mut self, name: String) -> u8 {
        let reg = self.next_free_register;

        if self.scopes.len() == 1 {
            self.top_level_names.insert(name.clone(), reg);
        }

        if let Some(current) = self.scopes.last_mut() {
            current.insert(name, reg);
            self.next_free_register += 1;
        }

        reg
    }
}

pub struct Compiler {
    pub errors: Vec<Error>,
    pub had_error: bool,

    pub constant_pool: Vec<Value>,
    contexts: Vec<Context>,
    std: StdDefinition,
    module_cache: HashMap<String, Value>,
    source: PathBuf,
}

impl Compiler {
    pub fn new(source: PathBuf) -> Self {
        Self {
            contexts: vec![Context::new()],
            constant_pool: vec![],
            errors: vec![],
            had_error: false,
            std: StdDefinition::get_core(),
            module_cache: HashMap::new(),
            source,
        }
    }

    pub fn with_natives(source: PathBuf, natives: Vec<NativeFunctionDef>) -> Self {
        let mut compiler = Self::new(source);
        compiler.std.functions.extend(natives);
        compiler
    }

    fn current(&mut self) -> &mut Context {
        self.contexts
            .last_mut()
            .expect("Compiler stack empty (no main stack)")
    }

    fn next_free_address(&mut self) -> u8 {
        let address = self.current().next_free_register;
        self.current().next_free_register += 1;
        return address;
    }

    fn compile_module(&mut self, source: String) -> Value {
        let full_path = self.source.join(&source);
        let canonical_path = fs::canonicalize(&full_path).unwrap_or(full_path);
        let path_str = canonical_path.to_str().unwrap().to_string();

        if let Some(cached) = self.module_cache.get(&path_str) {
            return cached.clone();
        }

        let raw_source =
            fs::read_to_string(&canonical_path).expect("Some error with reading import");
        let mut p = Parser::new(raw_source);
        let import_ast = p.parse_all().expect("Got error parser lol");

        let old_source = self.source.clone();
        self.source = canonical_path.parent().unwrap().to_path_buf();

        self.contexts.push(Context::new());

        for item in import_ast {
            self.compile(item);
        }

        // Create the exports object
        let obj_reg = self.next_free_address();
        let obj_val = Value::Object(Rc::new(RefCell::new(HashMap::new())));
        let obj_idx = match self.constant_pool.iter().position(|c| *c == obj_val) {
            Some(idx) => idx,
            None => {
                self.constant_pool.push(obj_val);
                self.constant_pool.len() - 1
            }
        };

        self.emit_op(OpCode::Load);
        self.emit(obj_reg);
        self.emit_op(OpCode::ConstObj);
        self.emit(obj_idx as u8);

        let top_level = self.current().top_level_names.clone();
        for (name, reg) in top_level {
            let hash = Value::Hash(Value::String(name).get_hash());
            let const_idx = match self.constant_pool.iter().position(|c| *c == hash) {
                Some(idx) => idx,
                None => {
                    self.constant_pool.push(hash);
                    self.constant_pool.len() - 1
                }
            };

            self.emit_op(OpCode::SetProperty);
            self.emit(obj_reg);
            self.emit(const_idx as u8);
            self.emit(reg);
        }

        self.emit_op(OpCode::Return);
        self.emit(obj_reg);

        let ctx = self.contexts.pop().expect("Empty contexts");
        let fun = Value::Fun {
            arity: 0,
            body: ctx.bytecode,
        };

        self.source = old_source;
        self.module_cache.insert(path_str, fun.clone());
        fun
    }

    pub fn compile_all(&mut self, ast: Vec<Ast>) -> Result<Vec<u8>, Vec<Error>> {
        for item in ast {
            if item != Ast::Ignore {
                self.compile(item);
            }
        }

        if self.had_error {
            return Err(self.errors.clone());
        } else {
            Ok(self.current().bytecode.clone())
        }
    }

    fn emit_op(&mut self, op: OpCode) {
        self.current().bytecode.push(op as u8);
    }

    fn emit(&mut self, val: u8) {
        self.current().bytecode.push(val);
    }

    fn emit16(&mut self, val: u16) {
        let bytes = (val as u16).to_le_bytes();

        self.emit(bytes[0]);
        self.emit(bytes[1]);
    }

    fn emit_vec(&mut self, val: Vec<u8>) {
        let mut temp = val.clone();

        self.current().bytecode.append(&mut temp);
    }

    fn emit_jump_op(&mut self, op: OpCode) -> usize {
        self.emit_op(op);

        self.emit_jump()
    }

    fn emit_jump(&mut self) -> usize {
        self.emit(0xff);
        self.emit(0xff);

        self.current().bytecode.len() - 2
    }

    fn patch_jump(&mut self, pos: usize) {
        let distance = self.current().bytecode.len() - (pos + 2);

        //todo check and error if it's too large

        let bytes = (distance as u16).to_le_bytes();

        self.current().bytecode[pos] = bytes[0];
        self.current().bytecode[pos + 1] = bytes[1];
    }

    fn patch_jump_to_target(&mut self, pos: usize, target: usize) {
        let bytes = (target as u16).to_le_bytes();

        self.current().bytecode[pos] = bytes[0];
        self.current().bytecode[pos + 1] = bytes[1];
    }

    fn compile_const(&mut self, value: ParserValue) {
        match value {
            ParserValue::Int(_) => self.emit_op(OpCode::ConstInt),
            ParserValue::Double(_) => self.emit_op(OpCode::ConstDouble),
            ParserValue::Bool(_) => self.emit_op(OpCode::ConstBool),
            ParserValue::String(_) => self.emit_op(OpCode::ConstString),
            ParserValue::Ref(ref name) => {
                if let Some(reg) = self.current().resolve_local(name) {
                    self.emit_op(OpCode::ConstReg);
                    self.emit(reg);
                    return;
                }

                self.emit_op(OpCode::ConstRef);
            }
            ParserValue::Fun { .. } => self.emit_op(OpCode::ConstFun),
            ParserValue::Object(_) | ParserValue::List(_) => self.emit_op(OpCode::ConstObj),
        };

        let converted = self.convert_const(value.clone());

        let temp = self.compile_value(converted.clone());

        self.emit_vec(temp);
    }

    fn find_stds(&self, ast: Ast) -> Vec<String> {
        match ast {
            Ast::Value(val) => match val {
                ParserValue::Ref(r) => {
                    return if let Some(_) = self.std.functions.iter().find(|f| f.name == r) {
                        vec![r]
                    } else {
                        vec![]
                    };
                }
                _ => vec![],
            },
            Ast::Declare { name: _, value } => self.find_stds(*value),
            Ast::Raise { value } | Ast::Return { value } => self.find_stds(*value),
            Ast::Call { what, args } => self
                .find_stds(*what)
                .into_iter()
                .chain(args.iter().map(|azt| self.find_stds(azt.clone())).flatten())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            Ast::Binary {
                left,
                right,
                operator: _,
            } => self
                .find_stds(*left)
                .into_iter()
                .chain(self.find_stds(*right))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            Ast::If {
                then_branch,
                else_branch,
                condition,
            } => self
                .find_stds(*condition)
                .into_iter()
                .chain(self.find_stds(*then_branch))
                .chain(self.find_stds(*else_branch.unwrap_or(Box::new(Ast::Ignore))))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            Ast::For { condition, body } => self
                .find_stds(*condition)
                .into_iter()
                .chain(self.find_stds(*body))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            Ast::ForEach {
                iterable,
                var_name: _,
                body,
            } => self
                .find_stds(*iterable)
                .into_iter()
                .chain(self.find_stds(*body))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            Ast::Block { code } => code
                .iter()
                .map(|azt| self.find_stds(azt.clone()))
                .flatten()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            Ast::Set { name: _, value } => self.find_stds(*value),
            _ => vec![],
        }
    }

    fn compile_value(&mut self, value: Value) -> Vec<u8> {
        return match value {
            Value::Int(i) => i.to_le_bytes().into(),
            Value::Double(d) => d.to_le_bytes().into(),
            Value::Bool(b) => vec![b as u8],
            Value::Ref(r) => {
                let mut register: Option<&u8> = None;
                let std = self.std.clone();

                for scope in &self.current().scopes {
                    if scope.contains_key(&r) {
                        register = Some(scope.get(&r).unwrap());
                        break;
                    }
                }

                if let Some(_std_func) = std.functions.iter().find(|f| f.name == r) {
                    if let Some(cached_reg) = self.current().loaded_natives.get(&r) {
                        return vec![*cached_reg];
                    }

                    let reg = self.next_free_address();

                    let hash = Value::Hash(Value::String(r.clone()).get_hash());

                    let idx = match self.constant_pool.iter().position(|c| *c == hash) {
                        Some(hash_idx) => hash_idx,
                        None => {
                            self.constant_pool.push(hash);

                            self.constant_pool.len() - 1
                        }
                    };

                    self.current().loaded_natives.insert(r.clone(), reg);

                    return vec![OpCode::LoadNative as u8, reg, idx as u8];
                }

                let reg = match register {
                    Some(reg) => *reg,
                    None => panic!("UndefinedResolve - {}", r),
                };

                vec![reg]
            }
            Value::Fun { arity: _, body: _ }
            | Value::Object(_)
            | Value::String(_)
            | Value::NativeFun(_)
            | Value::Hash(_) => match self.constant_pool.iter().position(|x| x == &value) {
                Some(expr) => vec![expr as u8],
                None => {
                    self.constant_pool.push(value);
                    vec![(self.constant_pool.len() - 1) as u8]
                }
            },
        };
    }

    fn compile(&mut self, ast: Ast) -> u8 {
        match ast {
            Ast::Declare { name, value } => {
                let address = self.current().add_local(name);

                match *value {
                    Ast::Value(raw) => {
                        self.emit_op(OpCode::Load);
                        self.emit(address);

                        self.compile_const(raw);
                    }
                    _ => {
                        let dest = self.compile(*value);

                        self.emit_op(OpCode::Load);
                        self.emit(address);

                        self.emit_op(OpCode::ConstReg);
                        self.emit(dest);
                    }
                };

                address
            }
            Ast::Value(val) => {
                if let ParserValue::Ref(ref ref_val) = val {
                    let reg = self.current().resolve_local(&ref_val);

                    if reg.is_some() {
                        return reg.unwrap();
                    }

                    if let Some(_std_func) = self.std.functions.iter().find(|f| f.name == ref_val) {
                        if let Some(addr) = self.current().loaded_natives.get(ref_val) {
                            return *addr;
                        }

                        let reg = self.next_free_address();

                        let hash = Value::Hash(Value::String(ref_val.to_string()).get_hash());

                        let idx = match self.constant_pool.iter().position(|c| *c == hash) {
                            Some(hash_idx) => hash_idx,
                            None => {
                                self.constant_pool.push(hash);

                                self.constant_pool.len() - 1
                            }
                        };

                        self.emit_vec(vec![OpCode::LoadNative as u8, reg, idx as u8]);
                        self.current().loaded_natives.insert(ref_val.clone(), reg);
                        return reg as u8;
                    }
                }

                let reg = self.next_free_address();

                self.emit_op(OpCode::Load);
                self.emit(reg);

                self.compile_const(val);
                reg
            }
            Ast::Return { value } | Ast::Raise { value } => {
                let reg = self.compile(*value);
                self.emit_op(OpCode::Return);
                self.emit(reg);
                0
            }
            Ast::Call { what, args } => {
                let (caller, final_args) = if let Ast::Dot { accessor, access } = *what {
                    let mut new_args = vec![*accessor];
                    new_args.extend(args);
                    (self.compile(*access), new_args)
                } else {
                    (self.compile(*what), args)
                };

                let mut compiled_args = vec![];
                for arg in &final_args {
                    compiled_args.push(self.compile(arg.clone()));
                }

                self.emit_op(OpCode::Call);

                let return_adr = self.next_free_address();
                self.emit(return_adr);

                self.emit(caller);

                self.emit(final_args.len().try_into().unwrap());

                compiled_args.iter().for_each(|arg| self.emit(*arg));

                return_adr
            }
            Ast::Binary {
                left,
                right,
                operator,
            } => {
                let compiled_left = self.compile(*left);
                let compiled_right = self.compile(*right);

                self.emit_op(OpCode::Binary);

                let op_code = match operator {
                    crate::parser::BinaryOperator::Add => 0,
                    crate::parser::BinaryOperator::Minus => 1,
                    crate::parser::BinaryOperator::Multiply => 2,
                    crate::parser::BinaryOperator::Divide => 3,
                    crate::parser::BinaryOperator::Equals => 4,
                    crate::parser::BinaryOperator::GreaterThan => 5,
                    crate::parser::BinaryOperator::LessThan => 6,
                    crate::parser::BinaryOperator::Modulo => 7,
                };

                self.emit(op_code);

                let reg = self.next_free_address();

                self.emit(reg);

                self.emit(compiled_left);
                self.emit(compiled_right);

                reg
            }
            Ast::If {
                then_branch,
                else_branch,
                condition,
            } => {
                let used_stds: Vec<_> = self
                    .find_stds(*then_branch.clone())
                    .into_iter()
                    .chain(self.find_stds(*else_branch.clone().unwrap_or(Box::new(Ast::Ignore))))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|s| Ast::Value(ParserValue::Ref(s)))
                    .collect();

                let _ = self.compile_all(used_stds);

                let cond = self.compile(*condition);

                self.emit_op(OpCode::JumpNot);
                self.emit(cond);
                let jump_to_else_pos = self.emit_jump();

                self.compile(*then_branch);

                if let Some(else_body) = else_branch {
                    let skip_else_pos = self.emit_jump_op(OpCode::JumpBy);

                    self.patch_jump(jump_to_else_pos);

                    self.compile(*else_body);

                    self.patch_jump(skip_else_pos);
                } else {
                    self.patch_jump(jump_to_else_pos);
                }

                0
            }
            Ast::ContinueCode => self.compile_continue(),
            Ast::BreakCode => self.compile_break(),
            Ast::Ignore => 0,
            Ast::For { condition, body } => {
                let start = self.current().bytecode.len();

                let cond_reg = self.compile(*condition);

                self.emit_op(OpCode::JumpNot);

                self.emit(cond_reg);

                let pos = self.emit_jump();

                self.current().loop_stack.push(LoopContext {
                    target: start,
                    jump_list: vec![],
                });

                self.compile(*body);

                self.emit_op(OpCode::JumpBack);

                let back_offset = (self.current().bytecode.len() + 2) - start;

                self.emit16(back_offset as u16);

                let loop_ctx = self.current().loop_stack.pop().unwrap();
                let loop_exit_pos = self.current().bytecode.len();

                self.patch_jump(pos);

                for placeholder in loop_ctx.jump_list {
                    self.patch_jump_to_target(placeholder, loop_exit_pos);
                }

                0
            }
            Ast::ForEach {
                iterable,
                var_name,
                body,
            } => {
                let iter = Ast::Declare {
                    name: "@iter".to_string(),
                    value: Box::new(Ast::Call {
                        what: Box::new(Ast::Value(ParserValue::Ref("iter_of".to_string()))),
                        args: vec![*iterable],
                    }),
                };

                let iter_ref = Ast::Value(ParserValue::Ref("@iter".to_string()));

                let has_next = Ast::Call {
                    what: Box::new(Ast::Value(ParserValue::Ref("has_next".to_string()))),
                    args: vec![iter_ref.clone()],
                };

                let decl = Ast::Declare {
                    name: var_name,
                    value: Box::new(Ast::Call {
                        what: Box::new(Ast::Value(ParserValue::Ref("get_next".to_string()))),
                        args: vec![iter_ref],
                    }),
                };

                let new_body = match *body {
                    Ast::Block { mut code } => {
                        let mut codes = vec![decl];
                        codes.append(&mut code);
                        Ast::Block { code: codes }
                    }
                    _ => Ast::Block {
                        code: vec![decl, *body],
                    },
                };

                self.compile(iter);

                self.compile(Ast::For {
                    condition: Box::new(has_next),
                    body: Box::new(new_body),
                })
            }
            Ast::Block { code } => {
                self.current().begin_scope();

                for ast in code {
                    self.compile(ast);
                }

                self.current().end_scope();

                0
            }

            Ast::Dot { accessor, access } => {
                if let Ast::Set { name, value } = *access {
                    return self.compile(Ast::Set {
                        name: Box::new(Ast::Dot {
                            accessor: accessor,
                            access: name,
                        }),
                        value: value,
                    });
                }
                self.emit_op(OpCode::GetProperty);
                let reg = self.next_free_address();
                self.emit(reg);

                if let Ast::Value(val) = *access {
                    let accessor = self.compile(*accessor);
                    self.emit(accessor);
                    let converted = self.convert_const(val);
                    let access = converted.get_hash();

                    self.constant_pool.push(Value::Hash(access));

                    self.emit((self.constant_pool.len() - 1) as u8);
                } else {
                    panic!("Unexpected type as value")
                }

                reg
            }

            Ast::Set { name, value } => match *name {
                Ast::Value(val) => match val {
                    ParserValue::Ref(name) => {
                        let dest = self.current().resolve_local(&name);

                        let reg = dest.unwrap_or_else(|| self.current().add_local(name));

                        if let Ast::Value(raw) = *value {
                            self.emit_op(OpCode::Load);
                            self.emit(reg);

                            self.compile_const(raw);
                        } else {
                            let res = self.compile(*value);

                            self.emit_op(OpCode::Load);
                            self.emit(reg);

                            self.emit_op(OpCode::ConstReg);

                            self.emit(res);
                        }
                        0
                    }
                    _ => panic!("WrongType"),
                },
                Ast::Dot { accessor, access } => {
                    let compiled_accessor = self.compile(*accessor);

                    let compiled_value = self.compile(*value);

                    let hash_access = if let Ast::Value(val) = *access {
                        let converted = self.convert_const(val);
                        let hash_access = converted.get_hash();

                        self.constant_pool.push(Value::Hash(hash_access));

                        (self.constant_pool.len() - 1) as u8
                    } else {
                        panic!("Unexpected value");
                    };

                    self.emit_op(OpCode::SetProperty);

                    self.emit(compiled_accessor);

                    self.emit(hash_access);

                    self.emit(compiled_value);

                    0
                }
                _ => panic!("WrongType"),
            },

            Ast::Import {
                import_type,
                import_map,
                source,
                alias: _,
            } => {
                if import_type == ImportType::Syntax || import_type == ImportType::Translation {
                    return 0;
                }

                let module_fun = self.compile_module(source);

                let fun_idx = match self.constant_pool.iter().position(|c| *c == module_fun) {
                    Some(idx) => idx,
                    None => {
                        self.constant_pool.push(module_fun);
                        self.constant_pool.len() - 1
                    }
                };

                let module_reg = self.next_free_address();
                self.emit_op(OpCode::Load);
                self.emit(module_reg);
                self.emit_op(OpCode::ConstFun);
                self.emit(fun_idx as u8);

                let res_reg = self.next_free_address();
                self.emit_op(OpCode::Call);
                self.emit(res_reg);
                self.emit(module_reg);
                self.emit(0);

                if let Some(map) = import_map {
                    for name in map {
                        let reg = self.current().add_local(name.clone());
                        let hash = Value::Hash(Value::String(name).get_hash());
                        let hash_idx = match self.constant_pool.iter().position(|c| *c == hash) {
                            Some(idx) => idx,
                            None => {
                                self.constant_pool.push(hash);
                                self.constant_pool.len() - 1
                            }
                        };

                        self.emit_op(OpCode::GetProperty);
                        self.emit(reg);
                        self.emit(res_reg);
                        self.emit(hash_idx as u8);
                    }
                }

                res_reg
            }
        }
    }

    fn compile_continue(&mut self) -> u8 {
        if let Some(loop_ctx) = self.current().loop_stack.last() {
            let target = loop_ctx.target;
            self.emit_op(OpCode::JumpBack);
            let offset = ((self.current().bytecode.len() + 2) - target).to_le_bytes();
            self.emit(offset[0]);
            self.emit(offset[1]);
        } else {
            panic!("Invalid keyword: 'continue' used out of loop");
        }

        0
    }

    fn compile_break(&mut self) -> u8 {
        let in_loop = !self.current().loop_stack.is_empty();

        if in_loop {
            let placeholder = self.emit_jump_op(OpCode::Jump);

            if let Some(loop_ctx) = self.current().loop_stack.last_mut() {
                loop_ctx.jump_list.push(placeholder);
            }
        } else {
            panic!("Cannot use 'break' outside of a loop");
        }

        0
    }

    fn convert_const(&mut self, val: ParserValue) -> Value {
        return match val {
            ParserValue::Int(int) => Value::Int(int),
            ParserValue::Double(dbl) => Value::Double(dbl),
            ParserValue::Bool(bol) => Value::Bool(bol),
            ParserValue::String(string) => Value::String(string),
            ParserValue::Ref(reference) => Value::Ref(reference),
            ParserValue::Fun { args, body } => {
                self.contexts.push(Context::new());

                let arity = args.len().try_into().unwrap();

                for arg in args {
                    self.current().add_local(arg);
                }

                self.compile((*body).into());

                let fun = self.contexts.pop().unwrap();

                Value::Fun {
                    arity,
                    body: fun.bytecode,
                }
            }
            ParserValue::Object(entries) => {
                self.contexts.push(Context::new());

                let mut entries_compiled = HashMap::new();

                for (key, value) in entries {
                    let converted = self.convert_const(key);
                    let val = self.convert_const(value);

                    entries_compiled.insert(converted.get_hash(), val);
                }

                self.contexts.pop();

                Value::Object(Rc::new(RefCell::new(entries_compiled)))
            }
            ParserValue::List(entries) => {
                let obj_entries = entries
                    .iter()
                    .enumerate()
                    .map(|(idx, val)| (ParserValue::Int(idx.try_into().unwrap()), val.clone()))
                    .collect();
                return self.convert_const(ParserValue::Object(obj_entries));
            }
        };
    }
}
