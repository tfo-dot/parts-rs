use crate::compiler::Compiler;
use crate::emitter::Emitter;
use crate::parser::Parser;
use crate::value::{NativeFunction, Value};
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
        Engine {
            import_path: std::env::current_dir().unwrap_or_default(),
            natives: vec![],
        }
    }

    pub fn with_import_path(path: PathBuf) -> Self {
        Engine {
            import_path: path,
            natives: vec![],
        }
    }

    pub fn register_native(
        &mut self,
        name: &'static str,
        arity: u8,
        call: fn(args: Vec<Value>) -> Result<Value, String>,
    ) {
        self.natives.push(NativeFunction {
            name,
            arity,
            call: std::sync::Arc::new(call),
        });
    }

    pub fn execute(&self, source: &str) -> Result<Option<Value>, String> {
        self.run(source).map(|res| res.value)
    }

    pub fn run(&self, source: &str) -> Result<ExecutionResult, String> {
        let mut parser = Parser::new(source.to_string());
        let ast = parser
            .parse_all()
            .map_err(|e| format!("Parser error: {:?}", e))?;

        let mut compiler = Compiler::with_natives(self.import_path.clone(), self.natives.clone());
        let ast = compiler.compile_all(ast).map_err(|e| {
            format!(
                "Compiler error: {}",
                e.iter()
                    .map(|err| format!("Line {}:{} - {}", err.line, err.column, err.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })?;

        let bytecode = Emitter {}.emit(ast);

        let mut vm = VM::with_natives(bytecode, compiler.constant_pool, self.natives.clone());
        let value = vm.run().map_err(|e| format!("VM error: {:?}", e))?;

        Ok(ExecutionResult {
            value,
            constants: vm.constants,
        })
    }
}
