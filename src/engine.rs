use crate::compiler::Compiler;
use crate::parser::Parser;
use crate::value::{NativeFunction, NativeFunctionDef, Value};
use crate::vm::VM;
use std::path::PathBuf;

pub struct ExecutionResult {
    pub value: Option<Value>,
    pub constants: Vec<Value>,
}

pub struct Engine {
    import_path: PathBuf,
    natives: Vec<NativeFunction>,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            import_path: std::env::current_dir().unwrap_or_default(),
            natives: Vec::new(),
        }
    }

    pub fn with_import_path(path: PathBuf) -> Self {
        Self {
            import_path: path,
            natives: Vec::new(),
        }
    }

    pub fn register_function(
        &mut self,
        name: &'static str,
        arity: u8,
        call: fn(args: Vec<Value>) -> Result<Value, String>,
    ) {
        self.natives.push(NativeFunction { name, arity, call });
    }

    pub fn execute(&self, source: &str) -> Result<Option<Value>, String> {
        self.run(source).map(|res| res.value)
    }

    pub fn run(&self, source: &str) -> Result<ExecutionResult, String> {
        let mut parser = Parser::new(source.to_string());
        let ast = parser
            .parse_all()
            .map_err(|e| format!("Parser error: {:?}", e))?;

        let native_defs: Vec<NativeFunctionDef> = self
            .natives
            .iter()
            .map(|f| NativeFunctionDef {
                name: f.name,
                arity: f.arity,
            })
            .collect();

        let mut compiler = Compiler::with_natives(self.import_path.clone(), native_defs);
        let bytecode = compiler.compile_all(ast).map_err(|e| {
            format!(
                "Compiler error: {}",
                e.iter()
                    .map(|err| format!("Line {}:{} - {}", err.line, err.column, err.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })?;

        let mut vm = VM::with_natives(bytecode, compiler.constant_pool, self.natives.clone());
        let value = vm.run().map_err(|e| format!("VM error: {:?}", e))?;

        Ok(ExecutionResult {
            value,
            constants: vm.constants,
        })
    }
}