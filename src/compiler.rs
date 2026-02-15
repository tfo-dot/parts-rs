use std::collections::HashMap;

use crate::define_opcodes;
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
    Load        = 0x00,

    // Constants
    ConstInt    = 0x01,
    ConstDouble = 0x02,
    ConstBool   = 0x03,
    ConstString = 0x04,
    ConstRef    = 0x05,
    ConstFun    = 0x06,
    ConstObj    = 0x07,

    // Flow Control
    Return      = 0x10,
    Call        = 0x11,
    Binary      = 0x12,
    Jump        = 0x13,
    JumpIf      = 0x14,
    JumpNot     = 0x15,
    JumpBack    = 0x16,

    //Other
    Dot         = 0x21,
    AssignDot   = 0x22,
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

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Double(f64),
    Bool(bool),
    String(String),
    Ref(String),
    Fun { arity: u8, body: Vec<u8> },
    Object(Vec<(Vec<u8>, Vec<u8>)>),
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

    fn compile(&mut self, ast: Ast) {
        match ast {
            Ast::Declare { name, value } => {
                let address = self.current().add_local(name);

                self.emit_op(OpCode::Load);
                self.emit(address);

                self.compile(*value);
            }
            Ast::Value(val) => {
                match val {
                    ParserValue::Int(_) => self.emit_op(OpCode::ConstInt),
                    ParserValue::Double(_) => self.emit_op(OpCode::ConstDouble),
                    ParserValue::Bool(_) => self.emit_op(OpCode::ConstBool),
                    ParserValue::String(_) => self.emit_op(OpCode::ConstString),
                    ParserValue::Ref(_) => self.emit_op(OpCode::ConstRef),
                    ParserValue::Fun { args: _, body: _ } => self.emit_op(OpCode::ConstFun),
                    ParserValue::Object(_) | ParserValue::List(_) => self.emit_op(OpCode::ConstObj),
                };

                let temp = self.compile_const(val);
                self.emit_vec(temp);
            }
            Ast::Return { value } => {
                self.emit_op(OpCode::Return);
                self.compile(*value);
            }
            Ast::Raise { value } => {
                self.emit_op(OpCode::Return);
                self.compile(*value);
            }
            Ast::Call { what, args } => {
                self.emit_op(OpCode::Call);
                self.compile(*what);

                self.emit(args.len().try_into().unwrap());

                for arg in args {
                    self.compile(arg);
                }
            }
            Ast::Binary {
                left,
                right,
                operator,
            } => {
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

                self.compile(*left);
                self.compile(*right);
            }
            Ast::If {
                then_branch,
                else_branch,
                condition,
            } => {
                self.emit_op(OpCode::JumpNot);

                self.compile(*condition);

                {
                    let pos = self.emit_jump();
                    self.compile(*then_branch);
                    self.patch_jump(pos);
                }

                {
                    let pos = self.emit_jump_op(OpCode::Jump);
                    match else_branch {
                        None => (),
                        Some(ast) => self.compile(*ast),
                    }
                    self.patch_jump(pos);
                }
            }
            Ast::ContinueCode => self.compile_continue(),
            Ast::BreakCode => self.compile_break(),
            Ast::Ignore => unreachable!(),
            Ast::For { condition, body } => {
                let start = self.current().bytecode.len();
                self.emit_op(OpCode::JumpNot);

                self.compile(*condition);

                let pos = self.emit_jump();

                self.current().loop_stack.push(LoopContext {
                    target: start,
                    jump_list: vec![],
                });

                self.compile(*body);

                self.emit_op(OpCode::JumpBack);

                let back_offset = (self.current().bytecode.len() + 2) - start;

                let bytes = (back_offset as u16).to_le_bytes();

                self.emit(bytes[0]);
                self.emit(bytes[1]);

                let loop_ctx = self.current().loop_stack.pop().unwrap();
                let loop_exit_pos = self.current().bytecode.len();

                self.patch_jump(pos);

                for placeholder in loop_ctx.jump_list {
                    self.patch_jump_to_target(placeholder, loop_exit_pos);
                }
            }
            Ast::Block { code } => {
                self.current().begin_scope();

                for ast in code {
                    self.compile(ast);
                }

                self.current().end_scope();
            }

            Ast::Dot { accessor, access } => {
                self.emit_op(OpCode::Dot);
                self.compile(*accessor);
                self.compile(*access);
            }

            Ast::Set { name, value } => match *name {
                Ast::Value(val) => match val {
                    ParserValue::Ref(name) => {
                        let dest = self.current().resolve_local(&name);

                        let reg = dest.unwrap_or_else(|| self.current().add_local(name));

                        self.emit_op(OpCode::Load);
                        self.emit(reg);

                        self.compile(*value);
                    }
                    _ => panic!("WrongType"),
                },
                Ast::Dot { accessor, access } => {
                    //TODO fix this it doesn't require ref to be a valid variable
                    self.emit_op(OpCode::AssignDot);
                    self.compile(*accessor);
                    self.compile(*access);
                    self.compile(*value);
                }
                _ => panic!("WrongType"),
            },
        };
    }

    fn compile_continue(&mut self) {
        if let Some(loop_ctx) = self.current().loop_stack.last() {
            let target = loop_ctx.target;
            self.emit_op(OpCode::JumpBack);
            let offset = ((self.current().bytecode.len() + 2) - target).to_le_bytes();
            self.emit(offset[0]);
            self.emit(offset[1]);
        } else {
            panic!("Invalid keyword: 'continue' used out of loop");
        }
    }

    fn compile_break(&mut self) {
        let in_loop = !self.current().loop_stack.is_empty();

        if in_loop {
            let placeholder = self.emit_jump_op(OpCode::Jump);

            if let Some(loop_ctx) = self.current().loop_stack.last_mut() {
                loop_ctx.jump_list.push(placeholder);
            }
        } else {
            panic!("Cannot use 'break' outside of a loop");
        }
    }

    fn compile_const(&mut self, val: ParserValue) -> Vec<u8> {
        return match val {
            ParserValue::Int(int) => int.to_le_bytes().to_vec(),
            ParserValue::Double(dbl) => dbl.to_le_bytes().to_vec(),
            ParserValue::Bool(bol) => vec![bol as u8],
            ParserValue::String(string) => vec![self.handle_string(string)],
            ParserValue::Ref(reference) => vec![self.resolve_ref(reference)],
            ParserValue::Fun { args, body } => vec![self.compile_fun(args, body)],
            ParserValue::Object(entries) => vec![self.compile_obj(entries)],
            ParserValue::List(values) => vec![self.compile_arr(values)],
        };
    }

    fn compile_fun(&mut self, args: Vec<String>, body: Box<Ast>) -> u8 {
        self.contexts.push(Context::new());

        let arity = args.len().try_into().unwrap();

        for arg in args {
            self.current().add_local(arg);
        }

        self.compile((*body).into());

        let fun = self.contexts.pop().unwrap();

        self.constant_pool.push(Value::Fun {
            arity,
            body: fun.bytecode,
        });

        return (self.constant_pool.len() - 1).try_into().unwrap();
    }

    fn handle_string(&mut self, string: String) -> u8 {
        let temp_val = Value::String(string.clone());

        return match self.constant_pool.iter().position(|x| x == &temp_val) {
            Some(expr) => expr.try_into().unwrap(),
            None => {
                self.constant_pool.push(temp_val);
                (self.constant_pool.len() - 1).try_into().unwrap()
            }
        };
    }

    fn resolve_ref(&mut self, reference: String) -> u8 {
        let mut register: Option<&u8> = None;

        for scope in &self.current().scopes {
            if scope.contains_key(&reference) {
                //TODO fix it so it works cross context
                register = Some(scope.get(&reference).unwrap());
                break;
            }
        }

        let reg = match register {
            Some(reg) => *reg,
            None => panic!("UndefinedResolve"),
        };

        return reg;
    }

    fn compile_obj(&mut self, entries: Vec<(ParserValue, ParserValue)>) -> u8 {
        self.contexts.push(Context::new());

        let mut entries_compiled = vec![];

        for (key, value) in entries {
            self.compile(Ast::Value(key));

            let key_vec = self.current().bytecode.clone();

            self.current().bytecode.clear();

            self.compile(Ast::Value(value));

            let value_vec = self.current().bytecode.clone();

            self.current().bytecode.clear();

            entries_compiled.push((key_vec, value_vec));
        }

        self.contexts.pop();

        self.constant_pool.push(Value::Object(entries_compiled));

        (self.constant_pool.len() - 1).try_into().unwrap()
    }

    fn compile_arr(&mut self, entries: Vec<ParserValue>) -> u8 {
        let obj_entries = entries
            .iter()
            .enumerate()
            .map(|(idx, val)| (ParserValue::Int(idx.try_into().unwrap()), val.clone()))
            .collect();
        return self.compile_obj(obj_entries);
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

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(
            res_vec,
            vec![OpCode::ConstInt as u8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn check_string_value() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::String("parts".to_string()))]);

        assert!(res.is_ok());

        let res_vec = res.unwrap();

        assert_eq!(res_vec, vec![OpCode::ConstString as u8, 0]);
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
            vec![OpCode::ConstString as u8, 0, OpCode::ConstString as u8, 0]
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
                OpCode::ConstString as u8,
                0,
                OpCode::ConstString as u8,
                1,
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
                name: "parts".to_string(),
                value: Box::new(Ast::Value(ParserValue::Bool(false))),
            },
            Ast::Value(ParserValue::Ref("parts".to_string())),
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
                OpCode::ConstRef as u8,
                0
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

        assert_eq!(res_vec, vec![OpCode::ConstFun as u8, 0]);

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 0,
                body: vec![OpCode::Return as u8, OpCode::ConstBool as u8, 0]
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

        assert_eq!(res_vec, vec![OpCode::ConstFun as u8, 0]);

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 1,
                body: vec![OpCode::Return as u8, OpCode::ConstBool as u8, 0]
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

        assert_eq!(res_vec, vec![OpCode::ConstFun as u8, 0]);

        assert_eq!(
            *c.constant_pool.last().unwrap(),
            Value::Fun {
                arity: 2,
                body: vec![OpCode::Return as u8, OpCode::ConstBool as u8, 0]
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
            vec![OpCode::Return as u8, OpCode::ConstBool as u8, 0]
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
            vec![OpCode::Return as u8, OpCode::ConstBool as u8, 0]
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
                OpCode::Call as u8,
                OpCode::ConstString as u8,
                0,
                1,
                OpCode::ConstInt as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
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
                OpCode::Binary as u8,
                0,
                OpCode::ConstBool as u8,
                0,
                OpCode::ConstBool as u8,
                0
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
                OpCode::JumpNot as u8,
                OpCode::ConstBool as u8,
                0,
                2,
                0,
                OpCode::ConstBool as u8,
                1,
                OpCode::Jump as u8,
                2,
                0,
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
                OpCode::JumpNot as u8,
                OpCode::ConstBool as u8,
                0,
                2,
                0,
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
                .is_ok_and(|out| out == vec![21, 3, 0, 6, 0, 22, 8, 0, 22, 11, 0])
        );
    }
    #[test]

    fn check_break() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::For {
            condition: Box::new(Ast::Value(ParserValue::Bool(false))),
            body: (Box::new(Ast::BreakCode)),
        }]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![21, 3, 0, 6, 0, 19, 11, 0, 22, 11, 0])
        );
    }

    #[test]
    fn check_obj_no_entries() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::Object(vec![]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::ConstObj as u8, 0])
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
                .is_ok_and(|out| out == vec![OpCode::ConstObj as u8, 0])
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

        assert!(entries.len() == 1);

        assert_eq!(
            entries[0],
            (
                vec![OpCode::ConstInt as u8, 100, 0, 0, 0, 0, 0, 0, 0],
                vec![OpCode::ConstBool as u8, 0]
            )
        );
    }

    #[test]
    fn check_arr_no_entries() {
        let mut c = Compiler::new();

        let res = c.compile_all(vec![Ast::Value(ParserValue::List(vec![]))]);

        assert!(
            res.clone()
                .is_ok_and(|out| out == vec![OpCode::ConstObj as u8, 0])
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
                .is_ok_and(|out| out == vec![OpCode::ConstObj as u8, 0])
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

        assert!(entries.len() == 2);

        assert_eq!(
            entries,
            vec![
                (
                    vec![OpCode::ConstInt as u8, 0, 0, 0, 0, 0, 0, 0, 0],
                    vec![OpCode::ConstInt as u8, 100, 0, 0, 0, 0, 0, 0, 0]
                ),
                (
                    vec![OpCode::ConstInt as u8, 1, 0, 0, 0, 0, 0, 0, 0],
                    vec![OpCode::ConstBool as u8, 0]
                )
            ]
        );
    }

    #[test]
    fn check_assign_with_declaration() {
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
    fn check_assign_no_declaration() {
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
            Ast::Declare {
                name: "y".to_string(),
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

        assert!(res.clone().is_ok_and(|out| out
            == vec![
                OpCode::Load as u8,
                0,
                OpCode::ConstObj as u8,
                0,
                OpCode::Load as u8,
                1,
                OpCode::ConstObj as u8,
                1,
                OpCode::AssignDot as u8,
                OpCode::ConstRef as u8,
                0,
                OpCode::ConstRef as u8,
                1,
                OpCode::ConstBool as u8,
                0
            ]));
    }
}
