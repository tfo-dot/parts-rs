use std::collections::HashMap;

use crate::{define_opcodes, impl_binary_op, impl_compare_op};
use crate::parser::Ast;
use crate::parser::Value as ParserValue;

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

    // Flow Control
    Return      = 0x10,
    Call        = 0x11,
    Binary      = 0x12,
    Jump        = 0x13,
    JumpIf      = 0x14,
    JumpNot     = 0x15,
    JumpBack    = 0x16,

    //Movement
    Load        = 0x20,
    GetProperty = 0x21,
    SetProperty = 0x22,
}

struct LoopContext {
    target: usize,
    jump_list: Vec<usize>,
}

struct Context {
    bytecode: Vec<u8>,

    scopes: Vec<HashMap<String, u8>>,
    next_free_register: u8,

    loop_stack: Vec<LoopContext>,
}

impl Context {
    fn new() -> Self {
        return Self {
            bytecode: vec![],
            scopes: vec![HashMap::new()],
            next_free_register: 0,
            loop_stack: vec![],
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

        if let Some(current) = self.scopes.last_mut() {
            current.insert(name, reg);
            self.next_free_register += 1;
        }

        reg
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum Value {
    Int(i64),
    Double(f64),
    Bool(bool),
    String(String),
    Ref(String),
    Fun { arity: u8, body: Vec<u8> },
    Object(Vec<(u64, Vec<u8>)>),
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
            Value::Object(_) | Value::Fun { .. } => {
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
            (l, r) => Err(format!(
                "operation not supported - mod ({:?}, {:?})", 
                l, r
            )),
        }
    }
}

impl_binary_op!(Add, add, +);
impl_binary_op!(Sub, sub, -);
impl_binary_op!(Mul, mul, *);
impl_binary_op!(Div, div, /);

impl_compare_op!(op_gt, >);
impl_compare_op!(op_lt, <);

impl Value {
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
}

struct Compiler {
    pub errors: Vec<Error>,
    pub had_error: bool,

    constant_pool: Vec<Value>,
    contexts: Vec<Context>,
}

impl Compiler {
    fn new() -> Self {
        Self {
            contexts: vec![Context::new()],
            constant_pool: vec![],
            errors: vec![],
            had_error: false,
        }
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

    fn compile_all(&mut self, ast: Vec<Ast>) -> Result<Vec<u8>, Vec<Error>> {
        for item in ast {
            self.compile(item);
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
            ParserValue::Ref(_) => self.emit_op(OpCode::ConstRef),
            ParserValue::Fun { .. } => self.emit_op(OpCode::ConstFun),
            ParserValue::Object(_) | ParserValue::List(_) => self.emit_op(OpCode::ConstObj),
        };

        let converted = self.convert_const(value.clone());

        let temp = self.compile_value(converted.clone());

        self.emit_vec(temp);
    }

    fn compile_value(&mut self, value: Value) -> Vec<u8> {
        return match value {
            Value::Int(i) => i.to_le_bytes().into(),
            Value::Double(d) => d.to_le_bytes().into(),
            Value::Bool(b) => vec![b as u8],
            Value::Ref(r) => {
                let mut register: Option<&u8> = None;

                for scope in &self.current().scopes {
                    if scope.contains_key(&r) {
                        //TODO fix it so it works cross context
                        register = Some(scope.get(&r).unwrap());
                        break;
                    }
                }

                let reg = match register {
                    Some(reg) => *reg,
                    None => panic!("UndefinedResolve"),
                };

                vec![reg]
            }
            Value::Fun { arity: _, body: _ }
            | Value::Object(_)
            | Value::String(_)
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

                self.emit_op(OpCode::Load);
                self.emit(address);

                if let Ast::Value(raw) = *value {
                    self.compile_const(raw);
                } else {
                    panic!("Non value passed as value")
                }

                address
            }
            Ast::Value(val) => {
                if let ParserValue::Ref(ref ref_val) = val {
                    let reg = self.current().resolve_local(&ref_val);

                    if reg.is_some() {
                        return reg.unwrap();
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
                let caller = self.compile(*what);
                let mut compiled_args = vec![];
                for arg in &args {
                    compiled_args.push(self.compile(arg.clone()));
                }

                self.emit_op(OpCode::Call);

                let return_adr = self.next_free_address();
                self.emit(return_adr);

                self.emit(caller);

                self.emit(args.len().try_into().unwrap());

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
                let cond = self.compile(*condition);

                self.emit_op(OpCode::JumpNot);

                self.emit(cond);

                {
                    let pos = self.emit_jump();
                    self.compile(*then_branch);
                    self.patch_jump(pos);
                }

                {
                    let pos = self.emit_jump_op(OpCode::Jump);
                    match else_branch {
                        None => 0,
                        Some(ast) => self.compile(*ast),
                    };
                    self.patch_jump(pos);
                }

                0
            }
            Ast::ContinueCode => self.compile_continue(),
            Ast::BreakCode => self.compile_break(),
            Ast::Ignore => unreachable!(),
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
            Ast::Block { code } => {
                self.current().begin_scope();

                for ast in code {
                    self.compile(ast);
                }

                self.current().end_scope();

                0
            }

            Ast::Dot { accessor, access } => {
                self.emit_op(OpCode::GetProperty);
                let reg = self.next_free_address();
                self.emit(reg);
                self.compile(*accessor);

                if let Ast::Value(val) = *access {
                    let converted = self.convert_const(val);
                    let access = converted.get_hash();

                    self.constant_pool.push(Value::Hash(access));

                    self.emit((self.constant_pool.len() - 1) as u8)
                } else {
                    panic!("Unexpected value");
                }

                reg
            }

            Ast::Set { name, value } => match *name {
                Ast::Value(val) => match val {
                    ParserValue::Ref(name) => {
                        let dest = self.current().resolve_local(&name);

                        let reg = dest.unwrap_or_else(|| self.current().add_local(name));

                        self.emit_op(OpCode::Load);
                        self.emit(reg);

                        if let Ast::Value(raw) = *value {
                            self.compile_const(raw);
                        } else {
                            panic!("Non value passed as value")
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

                let mut entries_compiled = vec![];

                for (key, value) in entries {
                    self.current().bytecode.clear();

                    self.compile_const(value);

                    let value_vec = self.current().bytecode.clone();

                    self.current().bytecode.clear();

                    let converted = self.convert_const(key);

                    entries_compiled.push((converted.get_hash(), value_vec));
                }

                self.contexts.pop();

                Value::Object(entries_compiled)
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

#[cfg(test)]
mod tests {
    use crate::compiler::{OpCode, Value};
    use crate::parser::Ast;
    use crate::parser::Value as ParserValue;

    use super::Compiler;

    #[test]
    fn check_empty() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![]);

        assert!(res.is_ok());
        assert_eq!(res.unwrap().iter().len(), 0)
    }

    #[test]
    fn check_declaration() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Declare {
            name: "x".to_string(),
            value: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstBool as u8, 0]
        )
    }

    #[test]
    fn check_inline_value() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::Int(0))]);

        assert!(res.is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstInt as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]));
    }

    #[test]
    fn check_string_value() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::String("parts".to_string()))]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstString as u8, 0]
        );
        assert_eq!(c.constant_pool[0], Value::String("parts".to_string()));
    }

    #[test]
    fn check_duplicate_string_value() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![
            Ast::Value(ParserValue::String("parts".to_string())),
            Ast::Value(ParserValue::String("parts".to_string())),
        ]);

        assert!(res.is_ok());
        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstString as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstString as u8,
                0
            ]
        );
        assert_eq!(c.constant_pool[0], Value::String("parts".to_string()));
    }

    #[test]
    fn check_multi_string_value() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![
            Ast::Value(ParserValue::String("parts".to_string())),
            Ast::Value(ParserValue::String("rust".to_string())),
            Ast::Value(ParserValue::String("parts".to_string())),
        ]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstString as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstString as u8,
                1,
                OpCode::Load as u8,
                2,
                OpCode::ConstString as u8,
                0
            ]
        );
        assert_eq!(c.constant_pool[0], Value::String("parts".to_string()));
        assert_eq!(c.constant_pool[1], Value::String("rust".to_string()));
    }

    #[test]
    fn check_ref() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![
            Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            },
            Ast::Declare {
                name: "y".to_string(),
                value: Box::new(Ast::Value(ParserValue::Ref("x".to_string()))),
            },
        ]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstRef as u8,
                0,
            ]
        )
    }

    #[test]
    fn check_fun_no_args() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::Fun {
            args: vec![],
            body: Box::new(Ast::Return {
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            }),
        })]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstFun as u8, 0]
        );

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 0,
                body: vec![
                    OpCode::Load as u8,
                    0,
                    OpCode::ConstBool as u8,
                    0,
                    OpCode::Return as u8,
                    0
                ]
            }
        )
    }

    #[test]
    fn check_fun_one_arg() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::Fun {
            args: vec!["n".to_string()],
            body: Box::new(Ast::Return {
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            }),
        })]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstFun as u8, 0]
        );

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 1,
                body: vec![
                    OpCode::Load as u8,
                    1,
                    OpCode::ConstBool as u8,
                    0,
                    OpCode::Return as u8,
                    1
                ]
            }
        )
    }

    #[test]
    fn check_fun_multiple_args() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::Fun {
            args: vec!["n".to_string(), "i".to_string()],
            body: Box::new(Ast::Return {
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            }),
        })]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::Load as u8, 0, OpCode::ConstFun as u8, 0]
        );

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 2,
                body: vec![
                    OpCode::Load as u8,
                    2,
                    OpCode::ConstBool as u8,
                    0,
                    OpCode::Return as u8,
                    2
                ]
            }
        )
    }

    #[test]
    fn check_return() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Return {
            value: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Return as u8,
                0
            ]
        );
    }

    #[test]
    fn check_raise() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Return {
            value: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Return as u8,
                0
            ]
        );
    }

    #[test]
    fn check_call() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Call {
            what: Box::new(Ast::Value(ParserValue::String("fib".to_string()))),
            args: vec![Ast::Value(ParserValue::Int(0))],
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstString as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstInt as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                OpCode::Call as u8,
                2,
                0,
                1,
                1,
            ]
        );
    }

    #[test]
    fn check_binary() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Binary {
            left: Box::new(Ast::Value(ParserValue::Bool(false))),
            right: Box::new(Ast::Value(ParserValue::Bool(false))),
            operator: crate::parser::BinaryOperator::Add,
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                0,
                OpCode::Binary as u8,
                0,
                2,
                0,
                1
            ]
        );
    }

    #[test]
    fn check_if() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::If {
            then_branch: Box::new(Ast::Value(ParserValue::Bool(true))),
            else_branch: Some(Box::new(Ast::Value(ParserValue::Bool(false)))),
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                4,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                1,
                OpCode::Jump as u8,
                4,
                0,
                OpCode::Load as u8,
                2,
                OpCode::ConstBool as u8,
                0,
            ]
        )
    }

    #[test]
    fn check_if_no_else() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::If {
            then_branch: Box::new(Ast::Value(ParserValue::Bool(true))),
            else_branch: None,
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                4,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                1,
                OpCode::Jump as u8,
                0,
                0,
            ]
        )
    }

    #[test]
    fn check_continue() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::For {
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
            body: (Box::new(Ast::ContinueCode)),
        }]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![   
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                6,
                0,
                OpCode::JumpBack as u8,
                11,
                0,
                OpCode::JumpBack as u8,
                14,
                0])
        );
    }
    #[test]

    fn check_break() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::For {
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
            body: (Box::new(Ast::BreakCode)),
        }]);

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::JumpNot as u8,
                0,
                6,
                0,
                OpCode::Jump as u8,
                14,
                0,
                OpCode::JumpBack as u8,
                14,
                0
            ]));
    }

    #[test]
    fn check_obj_no_entries() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::Object(vec![]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        assert!(
            c.constant_pool
                .get(0)
                .is_some_and(|x| if let Value::Object(entries) = x {
                    entries.len() == 0
                } else {
                    false
                })
        )
    }

    #[test]
    fn check_obj_with_entries() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::Object(vec![(
            ParserValue::Int(100),
            ParserValue::Bool(false),
        )]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        let obj = c.constant_pool.get(0);

        let entries = match obj {
            Some(Value::Object(entries)) => entries.clone(),
            None => {
                assert!(false, "object definition not found");
                vec![]
            }
            _ => panic!(),
        };

        assert!(entries.len() == 1);

        assert_eq!(
            entries[0],
            (Value::Int(100).get_hash(), vec![OpCode::ConstBool as u8, 0])
        );
    }

    #[test]
    fn check_arr_no_entries() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::List(vec![]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        assert!(
            c.constant_pool
                .get(0)
                .is_some_and(|x| if let Value::Object(entries) = x {
                    entries.len() == 0
                } else {
                    false
                })
        )
    }

    #[test]
    fn check_arr_with_entries() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::List(vec![
            ParserValue::Int(100),
            ParserValue::Bool(false),
        ]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstObj as u8, 0])
        );

        let obj = c.constant_pool.get(0);

        let entries = match obj {
            Some(Value::Object(entries)) => entries.clone(),
            None => {
                assert!(false, "object definition not found");
                vec![]
            }
            _ => todo!(),
        };

        assert_eq!(
            entries,
            vec![
                (
                    Value::Int(0).get_hash(),
                    vec![OpCode::ConstInt as u8, 100, 0, 0, 0, 0, 0, 0, 0]
                ),
                (Value::Int(1).get_hash(), vec![OpCode::ConstBool as u8, 0])
            ]
        );
    }

    #[test]
    fn check_assign_no_declaration() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Set {
            name: Box::from(Ast::Value(ParserValue::Ref("x".to_string()))),
            value: Box::from(Ast::Value(ParserValue::Bool(false))),
        }]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::Load as u8, 0, OpCode::ConstBool as u8, 0])
        );
    }

    #[test]
    fn check_assign_with_declaration() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![
            Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(ParserValue::Bool(true))),
            },
            Ast::Set {
                name: Box::from(Ast::Value(ParserValue::Ref("x".to_string()))),
                value: Box::from(Ast::Value(ParserValue::Bool(false))),
            },
        ]);

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                1,
                OpCode::Load as u8,
                0,
                OpCode::ConstBool as u8,
                0
            ]));
    }

    #[test]
    fn check_assign_with_dot() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![
            Ast::Declare {
                name: "x".to_string(),
                value: Box::new(Ast::Value(ParserValue::Object(vec![]))),
            },
            Ast::Set {
                name: Box::from(Ast::Dot {
                    accessor: Box::new(Ast::Value(ParserValue::Ref("x".to_string()))),
                    access: Box::new(Ast::Value(ParserValue::Ref("y".to_string()))),
                }),
                value: Box::from(Ast::Value(ParserValue::Bool(false))),
            },
        ]);

        let hash = Value::Ref("y".to_string()).get_hash();

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstObj as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstBool as u8,
                0,
                OpCode::SetProperty as u8,
                0, //Register
                1, //Const
                1  //Value register
            ]));

        assert_eq!(c.constant_pool[1], Value::Hash(hash.try_into().unwrap()))
    }
}
