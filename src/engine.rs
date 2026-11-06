use crate::compiler::Compiler;
use crate::emitter::Emitter;
use crate::optimize::{AstOptimizer, IrOptimizer};
use crate::parser::Parser;
use crate::value::{NativeFunction, Value};
use crate::vm::VM;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ModuleInstance {
    pub vm: VM,
    pub exports: Option<Value>,
}

impl ModuleInstance {
    pub fn new(vm: VM, exports: Option<Value>) -> Self {
        Self { vm, exports }
    }

    pub fn call_method(
        &mut self,
        method_name: &str,
        args: Vec<Value>,
    ) -> Result<Option<Value>, String> {
        if let Some(ref val) = self.exports {
            self.vm
                .call_method(val, method_name, args)
                .map_err(|e| format!("VM error: {}", e))
        } else {
            Err("Module instance has no exported object".to_string())
        }
    }

    pub fn call_function(
        &mut self,
        fun: &Value,
        args: Vec<Value>,
    ) -> Result<Option<Value>, String> {
        self.vm
            .call_value(fun, args)
            .map_err(|e| format!("VM error: {}", e))
    }

    pub fn has_method(&self, method_name: &str) -> bool {
        if let Some(Value::Object(ref obj_ref)) = self.exports {
            let hash = Value::String(method_name.to_string().into()).get_hash();
            obj_ref.borrow().contains_key(&hash)
        } else {
            false
        }
    }

    pub fn globals(&self) -> &[Value] {
        &self.vm.stack
    }

    pub fn constants(&self) -> &[Value] {
        &self.vm.constants
    }

    pub fn value(&self) -> Option<&Value> {
        self.exports.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub value: Option<Value>,
    pub constants: Vec<Value>,
    pub globals: Vec<Value>,
    pub instance: Option<ModuleInstance>,
}

impl ExecutionResult {
    pub fn into_instance(self) -> Option<ModuleInstance> {
        self.instance
    }
}

pub struct Engine {
    import_path: PathBuf,
    natives: Vec<NativeFunction>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
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
        call: impl Fn(&[Value]) -> Result<Value, String> + Send + Sync + 'static,
    ) {
        self.natives.push(NativeFunction {
            name,
            arity,
            call: std::sync::Arc::new(call),
        });
    }
    pub fn check(&self, source: &str) -> crate::diagnostic::Report {
        crate::tools::LanguageTools::check_with_import_path(source, None, self.import_path.clone())
    }

    pub fn execute(&self, source: &str) -> Result<Option<Value>, String> {
        self.run(source).map(|res| res.value)
    }
    pub fn instantiate(&self, source: &str) -> Result<ModuleInstance, String> {
        let res = self.run(source)?;
        res.instance
            .ok_or_else(|| "Failed to create module instance".to_string())
    }

    pub fn run(&self, source: &str) -> Result<ExecutionResult, String> {
        let mut parser = Parser::new(source.to_string());
        let mut ast = parser
            .parse_all()
            .map_err(|e| format!("Parser error: {}", e))?;

        let mut optimizer = AstOptimizer::new();
        optimizer.collect_all(&ast);
        let mut changed = true;
        while changed {
            changed = optimizer.optimize_all(&mut ast);
        }

        let mut compiler = Compiler::with_natives(self.import_path.clone(), self.natives.clone());
        compiler.set_source_text(source);
        compiler.optimize = true;
        let ir = compiler.compile_all(ast).map_err(|e| {
            format!(
                "Compiler error:\n{}",
                e.iter()
                    .map(|err| {
                        if err.line > 0 {
                            format!("Line {}:{} - {}", err.line, err.column, err.message)
                        } else {
                            format!("- {}", err.message)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })?;
        let ir = IrOptimizer::optimize(ir);
        let (bytecode, source_map) = Emitter::emit_with_source_map(ir);

        let mut vm = VM::with_natives(bytecode, compiler.constant_pool, self.natives.clone());
        vm.source_map = Some(std::rc::Rc::new(source_map));
        let value = vm.run().map_err(|e| format!("VM error: {}", e))?;

        let constants = vm.constants.clone();
        let globals = vm.stack.clone();
        let instance = Some(ModuleInstance::new(vm, value.clone()));

        Ok(ExecutionResult {
            value,
            constants,
            globals,
            instance,
        })
    }
}
