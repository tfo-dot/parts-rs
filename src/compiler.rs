use crate::emitter::Emitter;
pub use crate::emitter::IrOp;
use crate::optimize::{AstOptimizer, IrOptimizer};
use crate::parser::BinaryOperator;
use crate::parser::EnumVariant;
use crate::parser::ImportType;
use crate::parser::Parser;
use crate::parser::Value as ParserValue;
use crate::value::{Function, NativeFunction, Value};
use rustc_hash::{FxHashMap, FxHashSet};
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{LazyLock, Mutex};

use crate::parser::Ast;

static STD_AST_CACHE: LazyLock<Mutex<FxHashMap<String, Vec<Ast>>>> =
    LazyLock::new(|| Mutex::new(FxHashMap::default()));

enum StdTarget {
    Module(&'static str),
    Native(NativeFunction),
    Const(crate::std::StdConstValue),
    PartsFun(usize),
}
#[derive(Clone, Debug)]
pub struct Error {
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub level: ErrorLevel,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line > 0 {
            write!(f, "{}:{}: {}", self.line, self.column, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn to_diagnostic(
        &self,
        source: Option<&str>,
        file: Option<&str>,
    ) -> crate::diagnostic::Diagnostic {
        let level = match self.level {
            ErrorLevel::Error => crate::diagnostic::DiagnosticLevel::Error,
            ErrorLevel::Warning => crate::diagnostic::DiagnosticLevel::Warning,
        };

        let mut diag = crate::diagnostic::Diagnostic::new(level, &self.message);

        if self.line > 0 {
            diag = diag.with_location(self.line, self.column);
        }

        if let Some(src) = source {
            diag = diag.with_source(src);
        }

        if let Some(f) = file {
            diag = diag.with_file(f);
        }

        diag
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorLevel {
    Error,
    Warning,
}

struct LoopContext {
    start: usize,
    end: usize,
}

struct Context {
    ir_buff: Vec<IrOp>,

    scopes: Vec<FxHashMap<String, u8>>,
    module_aliases: Vec<FxHashMap<String, Option<String>>>,
    top_level_names: FxHashMap<String, u8>,
    top_level_module_aliases: FxHashMap<String, String>,
    next_free_register: u8,

    loop_stack: Vec<LoopContext>,
    scope_bases: Vec<u8>,
    local_count: u8,
}

impl Context {
    fn new() -> Self {
        Self {
            scopes: vec![FxHashMap::default()],
            module_aliases: vec![FxHashMap::default()],
            scope_bases: vec![0],
            top_level_names: FxHashMap::default(),
            top_level_module_aliases: FxHashMap::default(),
            next_free_register: 0,
            loop_stack: vec![],
            local_count: 0,

            ir_buff: vec![],
        }
    }

    fn resolve_local(&mut self, name: &str) -> Option<u8> {
        for scope in self.scopes.iter().rev() {
            if let Some(&reg) = scope.get(name) {
                return Some(reg);
            }
        }

        None
    }

    fn resolve_local_module_alias(&self, name: &str) -> Option<&str> {
        for scope in self.module_aliases.iter().rev() {
            if let Some(entry) = scope.get(name) {
                return entry.as_deref();
            }
        }
        None
    }

    fn set_module_alias(&mut self, name: String, mod_path: String) {
        if self.scopes.len() == 1 {
            self.top_level_module_aliases
                .insert(name.clone(), mod_path.clone());
        }
        if let Some(current) = self.module_aliases.last_mut() {
            current.insert(name, Some(mod_path));
        }
    }

    fn clear_module_alias(&mut self, name: &str) {
        if self.scopes.len() == 1 {
            self.top_level_module_aliases.remove(name);
        }
        if let Some(current) = self.module_aliases.last_mut() {
            current.insert(name.to_string(), None);
        }
    }

    fn begin_scope(&mut self) {
        self.scopes.push(FxHashMap::default());
        self.module_aliases.push(FxHashMap::default());
        self.scope_bases.push(self.local_count);
    }

    fn end_scope(&mut self) {
        self.scopes.pop();
        self.module_aliases.pop();
        if let Some(base) = self.scope_bases.pop() {
            self.local_count = base;
            self.next_free_register = base;
        }
    }
    fn add_local(&mut self, name: String) -> u8 {
        let reg = self.local_count;

        if self.scopes.len() == 1 {
            self.top_level_names.insert(name.clone(), reg);
        }

        if let Some(current) = self.scopes.last_mut() {
            current.insert(name, reg);
        }

        self.local_count += 1;
        self.next_free_register = self.local_count;

        reg
    }
}

pub struct Compiler {
    pub errors: Vec<Error>,
    pub had_error: bool,

    pub constant_pool: Vec<Value>,
    constant_map: FxHashMap<Value, usize>,
    pub enums: Vec<EnumDef>,
    contexts: Vec<Context>,
    extra_natives: FxHashMap<String, NativeFunction>,
    source: PathBuf,
    next_label_id: usize,
    pub optimize: bool,
    pub source_lines: Option<Vec<String>>,
    pub current_line: usize,
    pub current_col: usize,
    pub module_variables: rustc_hash::FxHashSet<String>,
    mutated_vars: FxHashSet<String>,
    any_std_field_mutated: bool,
    compiled_std_overlays: FxHashMap<String, usize>,
    compiled_std_overlay_exports: FxHashMap<(String, String), usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnumDef {
    name: String,
    variants: Vec<EnumVariant>,
    idx: usize,
}

impl Compiler {
    pub fn new(source: PathBuf) -> Self {
        let mut compiler = Self {
            contexts: vec![Context::new()],
            constant_pool: vec![],
            constant_map: FxHashMap::default(),
            errors: vec![],
            had_error: false,
            extra_natives: FxHashMap::default(),
            next_label_id: 0,
            source,
            enums: vec![],
            optimize: false,
            source_lines: None,
            current_line: 0,
            current_col: 0,
            module_variables: rustc_hash::FxHashSet::default(),
            mutated_vars: FxHashSet::default(),
            any_std_field_mutated: false,
            compiled_std_overlays: FxHashMap::default(),
            compiled_std_overlay_exports: FxHashMap::default(),
        };
        compiler.enums.push(EnumDef {
            name: "Result".to_string(),
            variants: vec![
                EnumVariant {
                    name: "Ok".to_string(),
                    fields: vec!["val".to_string()],
                },
                EnumVariant {
                    name: "Err".to_string(),
                    fields: vec!["err".to_string()],
                },
            ],
            idx: 0,
        });
        compiler.enums.push(EnumDef {
            name: "Option".to_string(),
            variants: vec![
                EnumVariant {
                    name: "Some".to_string(),
                    fields: vec!["val".to_string()],
                },
                EnumVariant {
                    name: "None".to_string(),
                    fields: vec![],
                },
            ],
            idx: 1,
        });

        compiler.optimize = false;
        compiler
    }

    pub fn with_natives(source: PathBuf, natives: Vec<NativeFunction>) -> Self {
        let mut compiler = Self::new(source);
        for n in natives {
            compiler.extra_natives.insert(n.name.to_string(), n);
        }
        compiler
    }

    fn lookup_global_native(&self, name: &str) -> Option<&NativeFunction> {
        self.extra_natives
            .get(name)
            .or_else(|| crate::std::core_global_by_name(name))
    }

    fn collect_mutated_vars(&mut self, nodes: &[Ast]) {
        for node in nodes {
            self.collect_mutated_node(node);
        }
    }

    fn collect_mutated_node(&mut self, node: &Ast) {
        match node {
            Ast::Declare { value, .. } | Ast::Return { value } => {
                self.collect_mutated_node(value);
            }
            Ast::Set { name, value } => {
                match &**name {
                    Ast::Value(ParserValue::Ref(var)) => {
                        self.mutated_vars.insert(var.clone());
                    }
                    Ast::Dot { .. } => {
                        let mut cur = &**name;
                        while let Ast::Dot { accessor, .. } = cur {
                            cur = accessor;
                        }
                        if let Ast::Value(ParserValue::Ref(root)) = cur {
                            self.mutated_vars.insert(root.clone());
                        }
                        self.any_std_field_mutated = true;
                    }
                    _ => {}
                }
                self.collect_mutated_node(name);
                self.collect_mutated_node(value);
            }
            Ast::Block { code } => {
                for item in code {
                    self.collect_mutated_node(item);
                }
            }
            Ast::Call { what, args } => {
                self.collect_mutated_node(what);
                for a in args {
                    self.collect_mutated_node(a);
                }
            }
            Ast::Binary { left, right, .. } => {
                self.collect_mutated_node(left);
                self.collect_mutated_node(right);
            }
            Ast::If {
                then_branch,
                else_branch,
                condition,
            } => {
                self.collect_mutated_node(condition);
                self.collect_mutated_node(then_branch);
                if let Some(e) = else_branch {
                    self.collect_mutated_node(e);
                }
            }
            Ast::For { condition, body } => {
                self.collect_mutated_node(condition);
                self.collect_mutated_node(body);
            }
            Ast::ForEach { iterable, body, .. } => {
                self.collect_mutated_node(iterable);
                self.collect_mutated_node(body);
            }
            Ast::Dot {
                accessor, access, ..
            } => {
                self.collect_mutated_node(accessor);
                self.collect_mutated_node(access);
            }
            Ast::Object(pairs) => {
                for (k, v) in pairs {
                    self.collect_mutated_node(k);
                    self.collect_mutated_node(v);
                }
            }
            Ast::Match { target, arms } => {
                self.collect_mutated_node(target);
                for arm in arms {
                    self.collect_mutated_node(&arm.body);
                }
            }
            Ast::Value(ParserValue::Fun { body, .. }) => {
                self.collect_mutated_node(body);
            }
            Ast::Value(ParserValue::EnumField { fields, .. }) => {
                for f in fields {
                    self.collect_mutated_node(f);
                }
            }
            _ => {}
        }
    }

    fn load_std_ast(&mut self, asset_path: &str) -> Option<Vec<Ast>> {
        {
            let cache = STD_AST_CACHE.lock().unwrap();
            if let Some(cached) = cache.get(asset_path) {
                return Some(cached.clone());
            }
        }
        let file = crate::Assets::get(asset_path)?;
        let content =
            String::from_utf8(file.data.to_vec()).expect("Invalid UTF-8 in embedded asset");
        let mut p = Parser::new(content);
        let mut ast = match p.parse_all() {
            Ok(ast) => ast,
            Err(e) => {
                self.error(
                    0,
                    0,
                    format!("syntax error in std module '{}': {}", asset_path, e),
                );
                return None;
            }
        };
        let mut opt = AstOptimizer::new();
        opt.collect_all(&ast);
        let mut changed = true;
        while changed {
            changed = opt.optimize_all(&mut ast);
        }
        STD_AST_CACHE
            .lock()
            .unwrap()
            .insert(asset_path.to_string(), ast.clone());
        Some(ast)
    }

    fn compile_ast_as_fun(&mut self, ast: Vec<Ast>) -> usize {
        let mut mod_ctx = Context::new();
        for item in &ast {
            if let Ast::Declare { name, .. } = item {
                let reg = mod_ctx.add_local(name.clone());
                mod_ctx.top_level_names.insert(name.clone(), reg);
            }
        }
        self.contexts.push(mod_ctx);
        for item in ast {
            self.compile(item);
            self.current().next_free_register = self.current().local_count;
        }
        let ctx = self.contexts.pop().expect("Empty contexts");
        let fun_ir = if self.optimize {
            IrOptimizer::optimize(ctx.ir_buff)
        } else {
            ctx.ir_buff
        };
        let frame_size = IrOp::compute_frame_size(0, &fun_ir);
        let code = Emitter {}.emit(fun_ir);
        let fun = Value::Fun(Rc::new(Function {
            arity: 0,
            frame_size,
            code: code.into(),
        }));
        self.get_or_add_constant(fun)
    }

    fn compile_std_overlay(&mut self, mod_path: &str, asset_path: &str) -> Option<usize> {
        if let Some(&idx) = self.compiled_std_overlays.get(mod_path) {
            return Some(idx);
        }
        let ast = self.load_std_ast(asset_path)?;
        let fun_idx = self.compile_ast_as_fun(ast);
        self.compiled_std_overlays
            .insert(mod_path.to_string(), fun_idx);
        Some(fun_idx)
    }

    fn try_extract_overlay_fun(
        &mut self,
        mod_path: &str,
        asset_path: &str,
        member_name: &str,
    ) -> Option<usize> {
        let key = (mod_path.to_string(), member_name.to_string());
        if let Some(&idx) = self.compiled_std_overlay_exports.get(&key) {
            return Some(idx);
        }
        let ast = self.load_std_ast(asset_path)?;
        let mut meaningful = ast.iter().filter(|node| {
            !matches!(
                node,
                Ast::Ignore | Ast::Value(ParserValue::String(_))
            )
        });
        let first = meaningful.next()?;
        if meaningful.next().is_some() {
            return None;
        }
        if let Ast::Return { value } = first
            && let Ast::Object(entries) = &**value
        {
            for (k_ast, v_ast) in entries {
                let matches_key = match k_ast {
                    Ast::Value(ParserValue::Ref(k)) | Ast::Value(ParserValue::String(k)) => {
                        k == member_name
                    }
                    _ => false,
                };
                if matches_key
                    && let Ast::Value(ParserValue::Fun { args, body }) = v_ast
                {
                    let fun_val = self.convert_const(ParserValue::Fun {
                        args: args.clone(),
                        body: body.clone(),
                    });
                    let idx = self.get_or_add_constant(fun_val);
                    self.compiled_std_overlay_exports.insert(key, idx);
                    return Some(idx);
                }
            }
        }
        None
    }

    fn emit_load_std_module(&mut self, dest: u8, mod_path: &'static str) {
        let reg = crate::std::std_registry();
        let path_idx = self.get_or_add_constant(Value::String(Rc::new(mod_path.to_string())));
        let overlay_idx = if mod_path == "std" {
            let mut bundle = FxHashMap::default();
            for (&sub_path, spec) in &reg.modules {
                if let Some(asset) = spec.overlay_asset
                    && let Some(fun_idx) = self.compile_std_overlay(sub_path, asset)
                {
                    let fun_val = self.constant_pool[fun_idx].clone();
                    bundle.insert(crate::std::hash_str(sub_path), fun_val);
                }
            }
            if bundle.is_empty() {
                u16::MAX as usize
            } else {
                self.get_or_add_constant(Value::Object(Rc::new(RefCell::new(bundle))))
            }
        } else if let Some(spec) = reg.modules.get(mod_path) {
            if let Some(asset) = spec.overlay_asset {
                self.compile_std_overlay(mod_path, asset)
                    .unwrap_or(u16::MAX as usize)
            } else {
                u16::MAX as usize
            }
        } else {
            u16::MAX as usize
        };
        self.add_inst(IrOp::LoadStdModule {
            dest,
            path_idx,
            overlay_idx,
        });
    }

    fn resolve_module_alias(&mut self, name: &str) -> Option<&'static str> {
        if self.any_std_field_mutated || self.mutated_vars.contains(name) {
            return None;
        }
        if self.current().resolve_local(name).is_some() {
            let mod_name = self.current().resolve_local_module_alias(name)?;
            return crate::std::std_registry()
                .modules
                .get_key_value(mod_name)
                .map(|(k, _)| *k);
        }
        if let Some(mod_name) = self.current().resolve_local_module_alias(name) {
            return crate::std::std_registry()
                .modules
                .get_key_value(mod_name)
                .map(|(k, _)| *k);
        }
        for ctx in self.contexts.iter().rev().skip(1) {
            if let Some(mod_name) = ctx.top_level_module_aliases.get(name) {
                return crate::std::std_registry()
                    .modules
                    .get_key_value(mod_name.as_str())
                    .map(|(k, _)| *k);
            }
            if ctx.top_level_names.contains_key(name) {
                return None;
            }
        }
        None
    }

    fn resolve_std_target(&mut self, ast: &Ast) -> Option<StdTarget> {
        let mut segments: Vec<&str> = Vec::new();
        let mut cur = ast;
        while let Ast::Dot {
            accessor,
            access,
            resolve: false,
        } = cur
        {
            if let Ast::Value(ParserValue::Ref(prop)) = &**access {
                segments.push(prop.as_str());
                cur = accessor;
            } else {
                return None;
            }
        }
        let base_name = match cur {
            Ast::Value(ParserValue::Ref(name)) => name.as_str(),
            _ => return None,
        };
        let mut current_mod = self.resolve_module_alias(base_name)?;
        if segments.is_empty() {
            return Some(StdTarget::Module(current_mod));
        }
        segments.reverse();
        let reg = crate::std::std_registry();
        for (i, &seg) in segments.iter().enumerate() {
            let spec = reg.modules.get(current_mod)?;
            let is_last = i + 1 == segments.len();
            if let Some(&sub_mod) = spec.submodules.get(seg) {
                current_mod = sub_mod;
                if is_last {
                    return Some(StdTarget::Module(current_mod));
                }
                continue;
            }
            if is_last {
                if let Some(native_fn) = spec.natives.get(seg) {
                    return Some(StdTarget::Native(native_fn.clone()));
                }
                if let Some(const_val) = spec.constants.get(seg) {
                    return Some(StdTarget::Const(const_val.clone()));
                }
                if let Some(asset) = spec.overlay_asset
                    && let Some(fun_idx) = self.try_extract_overlay_fun(current_mod, asset, seg)
                {
                    return Some(StdTarget::PartsFun(fun_idx));
                }
            }
            return None;
        }
        None
    }

    fn emit_std_const(&mut self, dest: u8, val: crate::std::StdConstValue) {
        match val {
            crate::std::StdConstValue::Int(i) => self.add_inst(IrOp::LoadInt { dest, val: i }),
            crate::std::StdConstValue::Double(d) => {
                self.add_inst(IrOp::LoadDouble { dest, val: d })
            }
            crate::std::StdConstValue::Bool(b) => self.add_inst(IrOp::LoadBool { dest, val: b }),
            crate::std::StdConstValue::Str(s) => {
                let idx = self.get_or_add_constant(Value::String(Rc::new(s.to_string())));
                self.add_inst(IrOp::LoadConst { dest, idx });
            }
        }
    }
    pub fn set_source_text(&mut self, text: &str) {
        self.source_lines = Some(text.lines().map(|s| s.to_string()).collect());
        self.current_line = 0;
        self.current_col = 0;
    }

    fn locate(&mut self, pattern: &str) {
        if let Some(ref lines) = self.source_lines {
            for (line_idx, line) in lines.iter().enumerate().skip(self.current_line) {
                let search_col = if line_idx == self.current_line {
                    self.current_col
                } else {
                    0
                };
                if search_col <= line.len()
                    && let Some(rel_col) = line[search_col..].find(pattern)
                {
                    let col_idx = search_col + rel_col;
                    self.current_line = line_idx;
                    self.current_col = col_idx + pattern.len();
                    self.add_inst(IrOp::SourceLocation {
                        line: line_idx + 1,
                        col: col_idx + 1,
                    });
                    break;
                }
            }
        }
    }

    pub fn error(&mut self, mut line: usize, mut column: usize, message: impl Into<String>) {
        if line == 0 && self.current_line > 0 {
            line = self.current_line + 1;
            column = self.current_col + 1;
        }
        self.errors.push(Error {
            line,
            column,
            message: message.into(),
            level: ErrorLevel::Error,
        });
        self.had_error = true;
    }

    pub fn warning(&mut self, line: usize, column: usize, message: impl Into<String>) {
        self.errors.push(Error {
            line,
            column,
            message: message.into(),
            level: ErrorLevel::Warning,
        });
    }

    fn current(&mut self) -> &mut Context {
        self.contexts
            .last_mut()
            .expect("Compiler stack empty (no main stack)")
    }

    fn next_free_address(&mut self) -> u8 {
        let address = self.current().next_free_register;
        if self.current().next_free_register == u8::MAX {
            self.error(
                0,
                0,
                "register overflow: exceeded maximum of 255 registers in frame",
            );
            return 255;
        }
        self.current().next_free_register += 1;
        address
    }

    fn get_or_add_constant(&mut self, val: Value) -> usize {
        if let Some(&idx) = self.constant_map.get(&val) {
            idx
        } else {
            let idx = self.constant_pool.len();
            self.constant_pool.push(val.clone());
            self.constant_map.insert(val, idx);
            idx
        }
    }

    fn new_label(&mut self) -> usize {
        let id = self.next_label_id;
        self.next_label_id += 1;
        id
    }

    fn compile_module(&mut self, source: String) -> Value {
        if source.starts_with("@std") {
            self.error(
                0,
                0,
                format!("Standard library module not found: '{}'", source),
            );
            return Value::Fun(Rc::new(Function {
                arity: 0,
                frame_size: 1,
                code: Rc::from([]),
            }));
        }
        let full_path = self.source.join(&source);
        let canonical_path = fs::canonicalize(&full_path).unwrap_or(full_path);
        let path_str = canonical_path.to_str().unwrap().to_string();
        let raw_source = match fs::read_to_string(&canonical_path) {
            Ok(c) => c,
            Err(e) => {
                self.error(0, 0, format!("failed to read import '{}': {}", path_str, e));
                return Value::Fun(Rc::new(Function {
                    arity: 0,
                    frame_size: 1,
                    code: Rc::from([]),
                }));
            }
        };
        let new_source_path = canonical_path.parent().unwrap().to_path_buf();

        let mut p = Parser::new(raw_source);
        let import_ast = match p.parse_all() {
            Ok(ast) => ast,
            Err(e) => {
                self.error(
                    0,
                    0,
                    format!("syntax error in imported module '{}': {}", source, e),
                );
                return Value::Fun(Rc::new(Function {
                    arity: 0,
                    frame_size: 1,
                    code: Rc::from([]),
                }));
            }
        };
        self.collect_mutated_vars(&import_ast);

        let old_source = self.source.clone();
        self.source = new_source_path;

        let mut mod_ctx = Context::new();

        for item in &import_ast {
            if let Ast::Declare { name, .. } = item {
                let reg = mod_ctx.add_local(name.clone());
                mod_ctx.top_level_names.insert(name.clone(), reg);
            }
        }

        self.contexts.push(mod_ctx);

        for item in import_ast {
            self.compile(item);

            self.current().next_free_register = self.current().local_count;
        }

        let obj_reg = self.next_free_address();
        let obj_val = Value::Object(Rc::new(RefCell::new(FxHashMap::default())));
        let obj_idx = self.get_or_add_constant(obj_val);

        self.add_inst(IrOp::LoadObject {
            dest: obj_reg,
            src: obj_idx,
        });

        let top_level = self.current().top_level_names.clone();
        let top_aliases = self.current().top_level_module_aliases.clone();
        for (name, reg) in top_level {
            if let Some(mod_path_str) = top_aliases.get(&name)
                && let Some((&mod_path, _)) = crate::std::std_registry()
                    .modules
                    .get_key_value(mod_path_str.as_str())
            {
                self.emit_load_std_module(reg, mod_path);
            }
            let hash = Value::Hash(Value::String(name.into()).get_hash());
            let const_idx = self.get_or_add_constant(hash);

            self.add_inst(IrOp::SetProperty {
                obj: obj_reg,
                key: const_idx,
                val: reg,
            });
        }

        self.add_inst(IrOp::Return { value: obj_reg });

        let ctx = self.contexts.pop().expect("Empty contexts");

        let fun_ir = if self.optimize {
            IrOptimizer::optimize(ctx.ir_buff)
        } else {
            ctx.ir_buff
        };

        let frame_size = IrOp::compute_frame_size(0, &fun_ir);
        let code = Emitter {}.emit(fun_ir);
        let fun = Value::Fun(Rc::new(Function {
            arity: 0,
            frame_size,
            code: code.into(),
        }));
        self.source = old_source;
        fun
    }

    pub fn compile_all(&mut self, ast: Vec<Ast>) -> Result<Vec<IrOp>, Vec<Error>> {
        self.collect_mutated_vars(&ast);
        for item in &ast {
            if let Ast::EnumDef { name, variants } = item {
                if let Some(pos) = self.enums.iter().position(|e| e.name == *name) {
                    let idx = self.enums[pos].idx;
                    self.enums[pos] = EnumDef {
                        name: name.clone(),
                        variants: variants.clone(),
                        idx,
                    };
                } else {
                    let enum_val = Value::EnumDefinition(self.enums.len().try_into().unwrap());
                    let idx = self.get_or_add_constant(enum_val);
                    self.enums.push(EnumDef {
                        name: name.clone(),
                        variants: variants.clone(),
                        idx,
                    });
                }
            }
        }
        for item in ast {
            if item != Ast::Ignore {
                self.compile(item);

                self.current().next_free_register = self.current().local_count;
            }
        }

        if self.had_error {
            Err(self.errors.clone())
        } else {
            Ok(self.current().ir_buff.clone())
        }
    }

    fn add_inst(&mut self, i: IrOp) {
        self.current().ir_buff.push(i);
    }

    fn compile(&mut self, ast: Ast) -> u8 {
        match ast {
            Ast::Declare { name, value } => {
                self.locate(&name);
                self.current().clear_module_alias(&name);
                if matches!(&*value, Ast::Import { .. }) || matches!(&*value, Ast::Dot { .. }) {
                    self.module_variables.insert(name.clone());
                }
                if let Ast::Import {
                    import_type: ImportType::Regular,
                    import_map: None,
                    source,
                    ..
                } = &*value
                    && let Some(mod_path) = crate::std::std_registry().resolve_import(source)
                {
                    if !self.any_std_field_mutated && !self.mutated_vars.contains(&name) {
                        let spec = &crate::std::std_registry().modules[mod_path];
                        let is_pure_parts = spec.natives.is_empty()
                            && spec.constants.is_empty()
                            && spec.submodules.is_empty()
                            && spec.overlay_asset.is_some();
                        if !is_pure_parts {
                            self.current()
                                .set_module_alias(name, mod_path.to_string());
                            return 0;
                        }
                    }
                    let address = self
                        .current()
                        .resolve_local(&name)
                        .unwrap_or_else(|| self.current().add_local(name));
                    self.emit_load_std_module(address, mod_path);
                    self.current().next_free_register = self.current().local_count;
                    return address;
                }
                if let Some(StdTarget::Module(mod_path)) = self.resolve_std_target(&value) {
                    if !self.any_std_field_mutated && !self.mutated_vars.contains(&name) {
                        let spec = &crate::std::std_registry().modules[mod_path];
                        let is_pure_parts = spec.natives.is_empty()
                            && spec.constants.is_empty()
                            && spec.submodules.is_empty()
                            && spec.overlay_asset.is_some();
                        if !is_pure_parts {
                            self.current()
                                .set_module_alias(name, mod_path.to_string());
                            return 0;
                        }
                    }
                    let address = self
                        .current()
                        .resolve_local(&name)
                        .unwrap_or_else(|| self.current().add_local(name));
                    self.emit_load_std_module(address, mod_path);
                    self.current().next_free_register = self.current().local_count;
                    return address;
                }
                let address = self
                    .current()
                    .resolve_local(&name)
                    .unwrap_or_else(|| self.current().add_local(name));
                match *value {
                    Ast::Value(ParserValue::EnumField { name, tag, fields }) => {
                        let (const_idx, tag_idx, args) = self.compile_enum_field(name, tag, fields);
                        self.add_inst(IrOp::LoadEnumField {
                            dest: address,
                            enum_idx: const_idx,
                            tag: tag_idx,
                            args,
                        });
                    }
                    Ast::Value(raw) => {
                        let v = self.convert_const(raw.clone());

                        match v {
                            Value::Int(i) => self.add_inst(IrOp::LoadInt {
                                dest: address,
                                val: i,
                            }),
                            Value::Double(d) => self.add_inst(IrOp::LoadDouble {
                                dest: address,
                                val: d,
                            }),
                            Value::Bool(b) => self.add_inst(IrOp::LoadBool {
                                dest: address,
                                val: b,
                            }),
                            Value::Ref(r) => {
                                if let Some(reg) = self.current().resolve_local(&r) {
                                    self.add_inst(IrOp::LoadReg {
                                        dest: address,
                                        src: reg,
                                    });
                                    return address;
                                }

                                for ctx in self.contexts.iter().rev().skip(1) {
                                    if let Some(&global_reg) = ctx.top_level_names.get(r.as_str()) {
                                        self.add_inst(IrOp::LoadGlobal {
                                            dest: address,
                                            src: global_reg,
                                        });
                                        return address;
                                    }
                                }

                                let hash = Value::Hash(Value::String(r.clone()).get_hash());
                                let const_idx = self.get_or_add_constant(hash);

                                self.add_inst(IrOp::LoadConst {
                                    dest: address,
                                    idx: const_idx,
                                });
                            }
                            Value::Fun(_)
                            | Value::Object(_)
                            | Value::String(_)
                            | Value::NativeFun(_)
                            | Value::Hash(_)
                            | Value::EnumDefinition(_)
                            | Value::EnumField { .. }
                            | Value::BoundMethod { .. }
                            | Value::Bytes(_) => {
                                let idx = self.get_or_add_constant(v);
                                self.add_inst(IrOp::LoadConst { dest: address, idx });
                            }
                        }
                    }
                    _ => {
                        let res = self.compile(*value);

                        self.add_inst(IrOp::LoadReg {
                            dest: address,
                            src: res,
                        });
                    }
                };

                self.current().next_free_register = self.current().local_count;

                address
            }
            Ast::Value(val) => {
                if let ParserValue::EnumField { name, tag, fields } = val {
                    let reg = self.next_free_address();
                    let (const_idx, tag_idx, args) = self.compile_enum_field(name, tag, fields);
                    self.add_inst(IrOp::LoadEnumField {
                        dest: reg,
                        enum_idx: const_idx,
                        tag: tag_idx,
                        args,
                    });
                    return reg;
                }

                if let ParserValue::Ref(ref_val) = &val {
                    if let Some(mod_path) = self.resolve_module_alias(ref_val) {
                        let reg = self.next_free_address();
                        self.emit_load_std_module(reg, mod_path);
                        return reg;
                    }
                    if let Some(reg) = self.current().resolve_local(ref_val) {
                        return reg;
                    }
                    for ctx in self.contexts.iter().rev().skip(1) {
                        if let Some(&global_reg) = ctx.top_level_names.get(ref_val) {
                            let dest_reg = self.next_free_address();

                            self.add_inst(IrOp::LoadGlobal {
                                dest: dest_reg,
                                src: global_reg,
                            });

                            return dest_reg;
                        }
                    }

                    if let Some(std_func) = self.lookup_global_native(ref_val).cloned() {
                        let reg = self.next_free_address();
                        let idx = self.get_or_add_constant(Value::NativeFun(std_func));
                        self.add_inst(IrOp::LoadConst { dest: reg, idx });
                        return reg;
                    }
                }

                let reg = self.next_free_address();
                let v = self.convert_const(val.clone());

                match v {
                    Value::Int(i) => self.add_inst(IrOp::LoadInt { dest: reg, val: i }),
                    Value::Double(d) => self.add_inst(IrOp::LoadDouble { dest: reg, val: d }),
                    Value::Bool(b) => self.add_inst(IrOp::LoadBool { dest: reg, val: b }),
                    Value::Ref(r) => {
                        if let Some(reg) = self.current().resolve_local(&r) {
                            self.add_inst(IrOp::LoadReg {
                                dest: reg,
                                src: reg,
                            });
                            return reg;
                        }

                        let hash = Value::Hash(Value::String(r.clone()).get_hash());
                        let const_idx = self.get_or_add_constant(hash);

                        self.add_inst(IrOp::LoadConst {
                            dest: reg,
                            idx: const_idx,
                        });
                    }
                    Value::Fun(_)
                    | Value::Object(_)
                    | Value::String(_)
                    | Value::NativeFun(_)
                    | Value::Hash(_)
                    | Value::EnumDefinition(_)
                    | Value::EnumField { .. }
                    | Value::BoundMethod { .. }
                    | Value::Bytes(_) => {
                        let idx = self.get_or_add_constant(v);
                        self.add_inst(IrOp::LoadConst { dest: reg, idx });
                    }
                }

                reg
            }
            Ast::Object(entries) => {
                let obj_reg = self.next_free_address();

                let is_fully_static = entries.iter().all(|(key_ast, val_ast)| {
                    matches!(
                        key_ast,
                        Ast::Value(
                            ParserValue::Int(_)
                                | ParserValue::Double(_)
                                | ParserValue::Bool(_)
                                | ParserValue::String(_)
                        )
                    ) && matches!(
                        val_ast,
                        Ast::Value(
                            ParserValue::Int(_)
                                | ParserValue::Double(_)
                                | ParserValue::Bool(_)
                                | ParserValue::String(_)
                        )
                    )
                });
                if is_fully_static {
                    let mut static_map = FxHashMap::default();

                    for (key_ast, val_ast) in entries {
                        let hash_key = if let Ast::Value(val) = key_ast {
                            match val {
                                ParserValue::Ref(ref name) => {
                                    Value::String(Rc::new(name.clone())).get_hash()
                                }
                                _ => {
                                    let converted = self.convert_const(val);
                                    converted.get_hash()
                                }
                            }
                        } else {
                            unreachable!()
                        };

                        let static_val = if let Ast::Value(val) = val_ast {
                            self.convert_const(val)
                        } else {
                            unreachable!()
                        };

                        static_map.insert(hash_key, static_val);
                    }

                    let obj_val = Value::Object(Rc::new(RefCell::new(static_map)));
                    let obj_idx = self.get_or_add_constant(obj_val);

                    self.add_inst(IrOp::LoadObject {
                        dest: obj_reg,
                        src: obj_idx,
                    });
                } else {
                    let obj_val = Value::Object(Rc::new(RefCell::new(FxHashMap::default())));
                    let obj_idx = self.get_or_add_constant(obj_val);

                    self.add_inst(IrOp::LoadObject {
                        dest: obj_reg,
                        src: obj_idx,
                    });

                    for (key_ast, val_ast) in entries {
                        if let Ast::Value(val) = key_ast {
                            let hash = match val {
                                ParserValue::Ref(ref name) => {
                                    Value::Hash(Value::String(Rc::new(name.clone())).get_hash())
                                }
                                _ => {
                                    let converted = self.convert_const(val);
                                    Value::Hash(converted.get_hash())
                                }
                            };
                            let hash_idx = self.get_or_add_constant(hash);

                            let val_reg = self.compile(val_ast);

                            self.add_inst(IrOp::SetProperty {
                                obj: obj_reg,
                                key: hash_idx,
                                val: val_reg,
                            });
                        } else {
                            let key_reg = self.compile(key_ast);
                            let val_reg = self.compile(val_ast);

                            self.add_inst(IrOp::SetPropertyDyn {
                                obj: obj_reg,
                                key: key_reg,
                                val: val_reg,
                            });
                        }
                    }
                }

                obj_reg
            }
            Ast::Return { value } => {
                self.locate("return");
                if self.contexts.len() > 1
                    && let Ast::Call { what, args } = &*value
                    && let Some(target) = self.resolve_std_target(what)
                {
                    match target {
                        StdTarget::Native(native_fn) => {
                            let mut compiled_args = vec![];
                            for arg in args {
                                compiled_args.push(self.compile(arg.clone()));
                            }
                            let idx = self.get_or_add_constant(Value::NativeFun(native_fn));
                            let return_adr = self.next_free_address();
                            self.add_inst(IrOp::CallNative {
                                dest: return_adr,
                                idx,
                                args: compiled_args,
                            });
                            self.add_inst(IrOp::Return { value: return_adr });
                            return 0;
                        }
                        StdTarget::PartsFun(fun_idx) => {
                            let caller = self.next_free_address();
                            self.add_inst(IrOp::LoadFun {
                                dest: caller,
                                src: fun_idx,
                            });
                            let mut compiled_args = vec![];
                            for arg in args {
                                compiled_args.push(self.compile(arg.clone()));
                            }
                            self.add_inst(IrOp::TailCall {
                                what: caller,
                                args: compiled_args,
                            });
                            return 0;
                        }
                        StdTarget::Const(_) | StdTarget::Module(_) => {}
                    }
                }
                if self.contexts.len() > 1
                    && let Ast::Call { what, args } = *value
                {
                    if let Ast::Value(ParserValue::Ref(ref fn_name)) = *what
                        && self.current().resolve_local(fn_name).is_none()
                        && !self
                            .contexts
                            .iter()
                            .rev()
                            .skip(1)
                            .any(|ctx| ctx.top_level_names.contains_key(fn_name))
                        && let Some(native_fn) = self.lookup_global_native(fn_name).cloned()
                    {
                        let mut compiled_args = vec![];
                        for arg in args {
                            compiled_args.push(self.compile(arg));
                        }
                        let idx = self.get_or_add_constant(Value::NativeFun(native_fn));
                        let return_adr = self.next_free_address();
                        self.add_inst(IrOp::CallNative {
                            dest: return_adr,
                            idx,
                            args: compiled_args,
                        });
                        self.add_inst(IrOp::Return { value: return_adr });
                        return 0;
                    }

                    let (caller, final_args) = if let Ast::Dot {
                        accessor,
                        access,
                        resolve: _,
                    } = *what.clone()
                    {
                        let is_module_accessor = match &*accessor {
                            Ast::Dot { .. } => true,
                            Ast::Value(ParserValue::Ref(name)) => {
                                self.module_variables.contains(name)
                            }
                            _ => false,
                        };
                        let is_ufcs = if is_module_accessor {
                            false
                        } else if let Ast::Value(ParserValue::Ref(ref name)) = *access {
                            self.current().resolve_local(name).is_some()
                                || self.lookup_global_native(name).is_some()
                        } else {
                            false
                        };

                        if is_ufcs {
                            if let Ast::Value(ParserValue::Ref(ref name)) = *access
                                && self.current().resolve_local(name).is_none()
                                && !self
                                    .contexts
                                    .iter()
                                    .rev()
                                    .skip(1)
                                    .any(|ctx| ctx.top_level_names.contains_key(name))
                                && let Some(native_fn) = self.lookup_global_native(name).cloned()
                            {
                                let mut new_args = vec![*accessor];
                                new_args.extend(args);
                                let mut compiled_args = vec![];
                                for arg in new_args {
                                    compiled_args.push(self.compile(arg));
                                }
                                let idx = self.get_or_add_constant(Value::NativeFun(native_fn));
                                let return_adr = self.next_free_address();
                                self.add_inst(IrOp::CallNative {
                                    dest: return_adr,
                                    idx,
                                    args: compiled_args,
                                });
                                self.add_inst(IrOp::Return { value: return_adr });
                                return 0;
                            }
                            let mut new_args = vec![*accessor];
                            new_args.extend(args);
                            (self.compile(*access), new_args)
                        } else {
                            (self.compile(*what), args)
                        }
                    } else {
                        (self.compile(*what), args)
                    };

                    let mut compiled_args = vec![];
                    for arg in &final_args {
                        compiled_args.push(self.compile(arg.clone()));
                    }

                    self.add_inst(IrOp::TailCall {
                        what: caller,
                        args: compiled_args,
                    });
                    return 0;
                }

                let reg = self.compile(*value);
                self.add_inst(IrOp::Return { value: reg });
                0
            }
            Ast::Call { what, args } => {
                if let Ast::Value(ParserValue::Ref(ref fn_name)) = *what {
                    self.locate(fn_name);
                }
                if let Some(target) = self.resolve_std_target(&what) {
                    match target {
                        StdTarget::Native(native_fn) => {
                            let mut compiled_args = vec![];
                            for arg in args {
                                compiled_args.push(self.compile(arg));
                            }
                            let idx = self.get_or_add_constant(Value::NativeFun(native_fn));
                            let return_adr = self.next_free_address();
                            self.add_inst(IrOp::CallNative {
                                dest: return_adr,
                                idx,
                                args: compiled_args,
                            });
                            self.current().next_free_register = return_adr + 1;
                            return return_adr;
                        }
                        StdTarget::PartsFun(fun_idx) => {
                            let caller = self.next_free_address();
                            self.add_inst(IrOp::LoadFun {
                                dest: caller,
                                src: fun_idx,
                            });
                            let mut compiled_args = vec![];
                            for arg in args {
                                compiled_args.push(self.compile(arg));
                            }
                            let return_adr = self.next_free_address();
                            self.add_inst(IrOp::Call {
                                dest: return_adr,
                                what: caller,
                                args: compiled_args,
                            });
                            self.current().next_free_register = return_adr + 1;
                            return return_adr;
                        }
                        StdTarget::Const(_) | StdTarget::Module(_) => {}
                    }
                }
                if let Ast::Value(ParserValue::Ref(ref fn_name)) = *what
                    && self.current().resolve_local(fn_name).is_none()
                    && !self
                        .contexts
                        .iter()
                        .rev()
                        .skip(1)
                        .any(|ctx| ctx.top_level_names.contains_key(fn_name))
                    && let Some(native_fn) = self.lookup_global_native(fn_name).cloned()
                {
                    let mut compiled_args = vec![];
                    for arg in args {
                        compiled_args.push(self.compile(arg));
                    }
                    let idx = self.get_or_add_constant(Value::NativeFun(native_fn));
                    let return_adr = self.next_free_address();
                    self.add_inst(IrOp::CallNative {
                        dest: return_adr,
                        idx,
                        args: compiled_args,
                    });
                    self.current().next_free_register = return_adr + 1;
                    return return_adr;
                }

                let (caller, final_args) = if let Ast::Dot {
                    accessor,
                    access,
                    resolve: _,
                } = *what.clone()
                {
                    let is_module_accessor = match &*accessor {
                        Ast::Dot { .. } => true,
                        Ast::Value(ParserValue::Ref(name)) => self.module_variables.contains(name),
                        _ => false,
                    };
                    let is_ufcs = if is_module_accessor {
                        false
                    } else if let Ast::Value(ParserValue::Ref(ref name)) = *access {
                        self.current().resolve_local(name).is_some()
                            || self.lookup_global_native(name).is_some()
                    } else {
                        false
                    };

                    if is_ufcs {
                        if let Ast::Value(ParserValue::Ref(ref name)) = *access
                            && self.current().resolve_local(name).is_none()
                            && !self
                                .contexts
                                .iter()
                                .rev()
                                .skip(1)
                                .any(|ctx| ctx.top_level_names.contains_key(name))
                            && let Some(native_fn) = self.lookup_global_native(name).cloned()
                        {
                            let mut new_args = vec![*accessor];
                            new_args.extend(args);
                            let mut compiled_args = vec![];
                            for arg in new_args {
                                compiled_args.push(self.compile(arg));
                            }
                            let idx = self.get_or_add_constant(Value::NativeFun(native_fn));
                            let return_adr = self.next_free_address();
                            self.add_inst(IrOp::CallNative {
                                dest: return_adr,
                                idx,
                                args: compiled_args,
                            });
                            self.current().next_free_register = return_adr + 1;
                            return return_adr;
                        }
                        let mut new_args = vec![*accessor];
                        new_args.extend(args);
                        (self.compile(*access), new_args)
                    } else {
                        (self.compile(*what), args)
                    }
                } else {
                    (self.compile(*what), args)
                };

                let mut compiled_args = vec![];
                for arg in &final_args {
                    compiled_args.push(self.compile(arg.clone()));
                }

                let return_adr = self.next_free_address();

                self.add_inst(IrOp::Call {
                    dest: return_adr,
                    what: caller,
                    args: compiled_args,
                });

                self.current().next_free_register = return_adr + 1;
                return_adr
            }
            Ast::Binary {
                left,
                right,
                operator,
            } => match operator {
                BinaryOperator::LogicalAnd => {
                    let result_reg = self.next_free_address();
                    let left_reg = self.compile(*left);
                    self.add_inst(IrOp::LoadReg {
                        dest: result_reg,
                        src: left_reg,
                    });
                    let end_label = self.new_label();
                    self.add_inst(IrOp::JumpNot {
                        condition: result_reg,
                        target: end_label,
                    });
                    let right_reg = self.compile(*right);
                    self.add_inst(IrOp::LoadReg {
                        dest: result_reg,
                        src: right_reg,
                    });
                    self.add_inst(IrOp::Label(end_label));
                    result_reg
                }
                BinaryOperator::LogicalOr => {
                    let result_reg = self.next_free_address();
                    let left_reg = self.compile(*left);
                    self.add_inst(IrOp::LoadReg {
                        dest: result_reg,
                        src: left_reg,
                    });
                    let eval_right_label = self.new_label();
                    let end_label = self.new_label();
                    self.add_inst(IrOp::JumpNot {
                        condition: result_reg,
                        target: eval_right_label,
                    });
                    self.add_inst(IrOp::Jump { target: end_label });
                    self.add_inst(IrOp::Label(eval_right_label));
                    let right_reg = self.compile(*right);
                    self.add_inst(IrOp::LoadReg {
                        dest: result_reg,
                        src: right_reg,
                    });
                    self.add_inst(IrOp::Label(end_label));
                    result_reg
                }
                _ => {
                    let compiled_left = self.compile(*left);
                    let compiled_right = self.compile(*right);

                    let reg = self.next_free_address();

                    self.add_inst(IrOp::Binary {
                        dest: reg,
                        op: operator,
                        left: compiled_left,
                        right: compiled_right,
                    });

                    self.current().next_free_register = reg + 1;
                    reg
                }
            },
            Ast::If {
                then_branch,
                else_branch,
                condition,
            } => {
                self.locate("if");
                let cond = self.compile(*condition);
                let else_label = self.new_label();
                let end_label = self.new_label();

                self.add_inst(IrOp::JumpNot {
                    condition: cond,
                    target: else_label,
                });

                self.compile(*then_branch);

                if let Some(else_body) = else_branch {
                    self.add_inst(IrOp::Jump { target: end_label });
                    self.add_inst(IrOp::Label(else_label));

                    self.compile(*else_body);

                    self.add_inst(IrOp::Label(end_label));
                } else {
                    self.add_inst(IrOp::Label(else_label));
                }

                0
            }
            Ast::ContinueCode => self.compile_continue(),
            Ast::BreakCode => self.compile_break(),
            Ast::Ignore => 0,
            Ast::For { condition, body } => {
                self.locate("for");
                let loop_base = self.current().local_count;
                let start_label = self.new_label();
                let end_label = self.new_label();

                self.add_inst(IrOp::Label(start_label));

                self.current().next_free_register = loop_base;
                let cond_reg = self.compile(*condition);
                self.add_inst(IrOp::JumpNot {
                    target: end_label,
                    condition: cond_reg,
                });
                self.current().next_free_register = loop_base;

                self.current().loop_stack.push(LoopContext {
                    start: start_label,
                    end: end_label,
                });

                self.compile(*body);

                self.current().loop_stack.pop();

                self.add_inst(IrOp::Jump {
                    target: start_label,
                });

                self.add_inst(IrOp::Label(end_label));
                self.current().next_free_register = loop_base;

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
                        what: Box::new(Ast::Value(ParserValue::Ref("__iter_of".to_string()))),
                        args: vec![*iterable],
                    }),
                };

                let iter_ref = Ast::Value(ParserValue::Ref("@iter".to_string()));

                let has_next = Ast::Call {
                    what: Box::new(Ast::Value(ParserValue::Ref("__has_next".to_string()))),
                    args: vec![iter_ref.clone()],
                };

                let decl = Ast::Declare {
                    name: var_name,
                    value: Box::new(Ast::Call {
                        what: Box::new(Ast::Value(ParserValue::Ref("__get_next".to_string()))),
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

                let mut last_reg = 0;
                for ast in code {
                    last_reg = self.compile(ast);
                    self.current().next_free_register = self.current().local_count;
                }

                self.current().end_scope();

                last_reg
            }

            Ast::Dot {
                accessor,
                access,
                resolve,
            } => {
                if let Ast::Set { name, value } = *access {
                    return self.compile(Ast::Set {
                        name: Box::new(Ast::Dot {
                            accessor,
                            access: name,
                            resolve,
                        }),
                        value,
                    });
                }
                let dot_ast = Ast::Dot {
                    accessor: accessor.clone(),
                    access: access.clone(),
                    resolve,
                };
                if let Some(target) = self.resolve_std_target(&dot_ast) {
                    let reg = self.next_free_address();
                    match target {
                        StdTarget::Module(mod_path) => {
                            self.emit_load_std_module(reg, mod_path);
                        }
                        StdTarget::Native(native_fn) => {
                            let idx = self.get_or_add_constant(Value::NativeFun(native_fn));
                            self.add_inst(IrOp::LoadConst { dest: reg, idx });
                        }
                        StdTarget::Const(const_val) => {
                            self.emit_std_const(reg, const_val);
                        }
                        StdTarget::PartsFun(fun_idx) => {
                            self.add_inst(IrOp::LoadFun {
                                dest: reg,
                                src: fun_idx,
                            });
                        }
                    }
                    self.current().next_free_register = reg + 1;
                    return reg;
                }

                let compiled_accessor = self.compile(*accessor);
                if resolve {
                    let compiled_access = self.compile(*access);
                    let reg = self.next_free_address();

                    self.add_inst(IrOp::GetPropertyDyn {
                        dest: reg,
                        obj: compiled_accessor,
                        key: compiled_access,
                    });
                    self.current().next_free_register = reg + 1;
                    reg
                } else if let Ast::Value(val) = *access {
                    let access_hash = match val {
                        ParserValue::Ref(ref name) => {
                            Value::String(Rc::new(name.clone())).get_hash()
                        }
                        _ => {
                            let converted = self.convert_const(val);
                            converted.get_hash()
                        }
                    };

                    let hash_val = Value::Hash(access_hash);
                    let hash_idx = self.get_or_add_constant(hash_val);

                    let reg = self.next_free_address();

                    self.add_inst(IrOp::GetProperty {
                        dest: reg,
                        obj: compiled_accessor,
                        key: hash_idx,
                    });
                    self.current().next_free_register = reg + 1;
                    reg
                } else {
                    panic!("AST Error: Static property access requires Ast::Value");
                }
            }

            Ast::Set { name, value } => match *name {
                Ast::Value(ParserValue::Ref(name)) => {
                    self.locate("=");
                    let dest = self.current().resolve_local(&name);

                    if dest.is_none() {
                        let mut found_global = None;
                        for ctx in self.contexts.iter().rev().skip(1) {
                            if let Some(&global_reg) = ctx.top_level_names.get(name.as_str()) {
                                found_global = Some(global_reg);
                                break;
                            }
                        }
                        if let Some(global_reg) = found_global {
                            let res = self.compile(*value);
                            self.add_inst(IrOp::StoreGlobal {
                                src: res,
                                dest: global_reg,
                            });
                            return res;
                        }
                    }

                    let lhs_reg = dest.unwrap_or_else(|| self.current().add_local(name));

                    if let Ast::Value(ParserValue::EnumField { name, tag, fields }) = *value {
                        let (const_idx, tag_idx, args) = self.compile_enum_field(name, tag, fields);
                        self.add_inst(IrOp::LoadEnumField {
                            dest: lhs_reg,
                            enum_idx: const_idx,
                            tag: tag_idx,
                            args,
                        });
                    } else if let Ast::Value(raw) = *value {
                        let v = self.convert_const(raw.clone());

                        match v {
                            Value::Int(i) => self.add_inst(IrOp::LoadInt {
                                dest: lhs_reg,
                                val: i,
                            }),
                            Value::Double(d) => self.add_inst(IrOp::LoadDouble {
                                dest: lhs_reg,
                                val: d,
                            }),
                            Value::Bool(b) => self.add_inst(IrOp::LoadBool {
                                dest: lhs_reg,
                                val: b,
                            }),
                            Value::Ref(r) => {
                                if let Some(rhs_reg) = self.current().resolve_local(&r) {
                                    self.add_inst(IrOp::LoadReg {
                                        dest: lhs_reg,
                                        src: rhs_reg,
                                    });
                                    return lhs_reg;
                                }

                                let hash = Value::Hash(Value::String(r.clone()).get_hash());
                                let hash_const = self.get_or_add_constant(hash);

                                self.add_inst(IrOp::LoadConst {
                                    dest: lhs_reg,
                                    idx: hash_const,
                                });
                            }
                            Value::Fun(_)
                            | Value::Object(_)
                            | Value::String(_)
                            | Value::NativeFun(_)
                            | Value::Hash(_)
                            | Value::EnumDefinition(_)
                            | Value::EnumField { .. }
                            | Value::BoundMethod { .. }
                            | Value::Bytes(_) => {
                                let idx = self.get_or_add_constant(v);
                                self.add_inst(IrOp::LoadConst { dest: lhs_reg, idx });
                            }
                        }
                    } else {
                        let res = self.compile(*value);

                        self.add_inst(IrOp::LoadReg {
                            dest: lhs_reg,
                            src: res,
                        });
                    }
                    0
                }
                Ast::Dot {
                    accessor,
                    access,
                    resolve,
                } => {
                    let compiled_accessor = self.compile(*accessor);
                    let compiled_value = self.compile(*value);

                    if resolve {
                        let compiled_access = self.compile(*access);

                        self.add_inst(IrOp::SetPropertyDyn {
                            obj: compiled_accessor,
                            key: compiled_access,
                            val: compiled_value,
                        });
                    } else if let Ast::Value(val) = *access {
                        let hash_access = match val {
                            ParserValue::Ref(ref name) => {
                                Value::String(Rc::new(name.clone())).get_hash()
                            }
                            _ => {
                                let converted = self.convert_const(val);
                                converted.get_hash()
                            }
                        };

                        let hash_val = Value::Hash(hash_access);
                        let hash_idx = self.get_or_add_constant(hash_val);

                        self.add_inst(IrOp::SetProperty {
                            obj: compiled_accessor,
                            key: hash_idx,
                            val: compiled_value,
                        });
                    } else {
                        panic!("AST Error: Static property assignment requires Ast::Value");
                    }

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

                if let Some(mod_path) = crate::std::std_registry().resolve_import(&source) {
                    if let Some(map) = import_map {
                        let mut mod_reg_opt = None;
                        for name in map {
                            let reg = self.current().add_local(name.clone());
                            let spec = &crate::std::std_registry().modules[mod_path];
                            if let Some(&sub_mod) = spec.submodules.get(name.as_str()) {
                                self.emit_load_std_module(reg, sub_mod);
                            } else if let Some(native_fn) = spec.natives.get(name.as_str()) {
                                let idx =
                                    self.get_or_add_constant(Value::NativeFun(native_fn.clone()));
                                self.add_inst(IrOp::LoadConst { dest: reg, idx });
                            } else if let Some(const_val) = spec.constants.get(name.as_str()) {
                                self.emit_std_const(reg, const_val.clone());
                            } else if let Some(asset) = spec.overlay_asset
                                && let Some(fun_idx) =
                                    self.try_extract_overlay_fun(mod_path, asset, &name)
                            {
                                self.add_inst(IrOp::LoadFun {
                                    dest: reg,
                                    src: fun_idx,
                                });
                            } else {
                                let mod_reg = match mod_reg_opt {
                                    Some(r) => r,
                                    None => {
                                        let r = self.next_free_address();
                                        self.emit_load_std_module(r, mod_path);
                                        mod_reg_opt = Some(r);
                                        r
                                    }
                                };
                                let hash = Value::Hash(Value::String(name.into()).get_hash());
                                let hash_idx = self.get_or_add_constant(hash);
                                self.add_inst(IrOp::GetProperty {
                                    dest: reg,
                                    obj: mod_reg,
                                    key: hash_idx,
                                });
                            }
                        }
                        return 0;
                    }

                    let res_reg = self.next_free_address();
                    self.emit_load_std_module(res_reg, mod_path);
                    return res_reg;
                }

                let module_fun = self.compile_module(source);

                let fun_idx = self.get_or_add_constant(module_fun);

                let module_reg = self.next_free_address();

                self.add_inst(IrOp::LoadFun {
                    dest: module_reg,
                    src: fun_idx,
                });

                let res_reg = self.next_free_address();

                self.add_inst(IrOp::Call {
                    dest: res_reg,
                    what: module_reg,
                    args: vec![],
                });

                if let Some(map) = import_map {
                    for name in map {
                        let reg = self.current().add_local(name.clone());
                        let hash = Value::Hash(Value::String(name.into()).get_hash());
                        let hash_idx = self.get_or_add_constant(hash);

                        self.add_inst(IrOp::GetProperty {
                            dest: reg,
                            obj: res_reg,
                            key: hash_idx,
                        });
                    }
                }

                res_reg
            }
            Ast::EnumDef { name, variants } => {
                if let Some(pos) = self.enums.iter().position(|e| e.name == name) {
                    let idx = self.enums[pos].idx;
                    self.enums[pos] = EnumDef {
                        name,
                        variants,
                        idx,
                    };
                } else {
                    let enum_val = Value::EnumDefinition(self.enums.len().try_into().unwrap());
                    let idx = self.get_or_add_constant(enum_val);
                    self.enums.push(EnumDef {
                        name,
                        variants,
                        idx,
                    });
                }

                0
            }
            Ast::Match { target, arms } => {
                use crate::parser::MatchPattern;
                let target_reg = self.compile(*target);
                let result_reg = self.next_free_address();
                let end_match_label = self.new_label();
                let match_base = self.current().next_free_register;

                for arm in arms {
                    let next_arm_label = self.new_label();
                    self.current().next_free_register = match_base;
                    self.current().local_count = match_base;
                    self.current().begin_scope();
                    match arm.pattern {
                        MatchPattern::Enum { name, tag, fields } => {
                            let enum_idx = match self.enums.iter().position(|e| e.name == *name) {
                                Some(idx) => idx,
                                None => {
                                    self.error(
                                        0,
                                        0,
                                        format!(
                                            "referencing enum definition that doesn't exist: '{}'",
                                            name
                                        ),
                                    );
                                    continue;
                                }
                            };
                            let enum_def = self.enums[enum_idx].clone();
                            let tag_idx = enum_def.variants.iter().position(|v| v.name == *tag);
                            let tag_idx = if let Some(idx) = tag_idx {
                                idx
                            } else {
                                self.error(
                                    0,
                                    0,
                                    format!(
                                        "referencing enum field that doesn't exist: '{}::{}'",
                                        name, tag
                                    ),
                                );
                                continue;
                            };
                            let tag_info = &enum_def.variants[tag_idx];

                            if fields.len() != tag_info.fields.len() {
                                self.error(
                                    0,
                                    0,
                                    format!(
                                        "pattern for '{}::{}' expected {} fields, got {}",
                                        name,
                                        tag,
                                        tag_info.fields.len(),
                                        fields.len()
                                    ),
                                );
                                continue;
                            }

                            let check_reg = self.next_free_address();
                            self.add_inst(IrOp::MatchEnum {
                                dest: check_reg,
                                src: target_reg,
                                enum_idx,
                                tag: tag_idx as u8,
                            });

                            self.add_inst(IrOp::JumpNot {
                                target: next_arm_label,
                                condition: check_reg,
                            });

                            for (i, field_binding) in fields.into_iter().enumerate() {
                                if field_binding != "_" {
                                    let field_def_name = &tag_info.fields[i];
                                    let hash = Value::Hash(
                                        Value::String(Rc::new(field_def_name.clone())).get_hash(),
                                    );
                                    let hash_idx = self.get_or_add_constant(hash);

                                    let field_reg = self.current().add_local(field_binding);
                                    self.add_inst(IrOp::GetProperty {
                                        dest: field_reg,
                                        obj: target_reg,
                                        key: hash_idx,
                                    });
                                }
                            }
                        }
                        MatchPattern::Value(val) => {
                            let val_reg = self.next_free_address();
                            let v = self.convert_const(val);
                            match v {
                                Value::Int(i) => self.add_inst(IrOp::LoadInt {
                                    dest: val_reg,
                                    val: i,
                                }),
                                Value::Double(d) => self.add_inst(IrOp::LoadDouble {
                                    dest: val_reg,
                                    val: d,
                                }),
                                Value::Bool(b) => self.add_inst(IrOp::LoadBool {
                                    dest: val_reg,
                                    val: b,
                                }),
                                _ => {
                                    let idx = self.get_or_add_constant(v);
                                    self.add_inst(IrOp::LoadConst { dest: val_reg, idx });
                                }
                            }

                            let cmp_reg = self.next_free_address();
                            self.add_inst(IrOp::Binary {
                                dest: cmp_reg,
                                op: BinaryOperator::Equals,
                                left: target_reg,
                                right: val_reg,
                            });

                            self.add_inst(IrOp::JumpNot {
                                target: next_arm_label,
                                condition: cmp_reg,
                            });
                        }
                        MatchPattern::Wildcard(binding) => {
                            if let Some(var_name) = binding
                                && var_name != "_"
                            {
                                let bound_reg = self.current().add_local(var_name);
                                self.add_inst(IrOp::LoadReg {
                                    dest: bound_reg,
                                    src: target_reg,
                                });
                            }
                        }
                    }

                    let body_reg = self.compile(*arm.body);
                    self.add_inst(IrOp::LoadReg {
                        dest: result_reg,
                        src: body_reg,
                    });

                    self.current().end_scope();

                    self.add_inst(IrOp::Jump {
                        target: end_match_label,
                    });
                    self.add_inst(IrOp::Label(next_arm_label));
                }

                self.add_inst(IrOp::Label(end_match_label));
                result_reg
            }
        }
    }

    fn compile_continue(&mut self) -> u8 {
        if let Some(loop_ctx) = self.current().loop_stack.last() {
            let start = loop_ctx.start;
            self.add_inst(IrOp::Jump { target: start });
        } else {
            self.error(0, 0, "cannot use 'continue' outside of a loop");
        }

        0
    }

    fn compile_break(&mut self) -> u8 {
        if let Some(loop_ctx) = self.current().loop_stack.last() {
            let end = loop_ctx.end;
            self.add_inst(IrOp::Jump { target: end });
        } else {
            self.error(0, 0, "cannot use 'break' outside of a loop");
        }

        0
    }

    fn convert_const(&mut self, val: ParserValue) -> Value {
        match val {
            ParserValue::Int(int) => Value::Int(int),
            ParserValue::Double(dbl) => Value::Double(dbl),
            ParserValue::Bool(bol) => Value::Bool(bol),
            ParserValue::String(string) => Value::String(string.into()),
            ParserValue::Ref(reference) => {
                if let Some(native) = self.lookup_global_native(&reference) {
                    return Value::NativeFun(native.clone());
                }
                Value::Ref(reference.into())
            }
            ParserValue::Fun { args, body } => {
                self.contexts.push(Context::new());
                let arity = args.len().try_into().unwrap();

                for arg in args {
                    self.current().add_local(arg);
                }

                self.compile(*body);

                if !matches!(self.current().ir_buff.last(), Some(IrOp::Return { .. })) {
                    let null_reg = self.next_free_address();
                    self.add_inst(IrOp::LoadBool {
                        dest: null_reg,
                        val: false,
                    });
                    self.add_inst(IrOp::Return { value: null_reg });
                }
                let fun = self.contexts.pop().unwrap();
                let fun_ir = if self.optimize {
                    IrOptimizer::optimize(fun.ir_buff)
                } else {
                    fun.ir_buff
                };
                let frame_size = IrOp::compute_frame_size(arity, &fun_ir);
                let code = Emitter {}.emit(fun_ir);

                Value::Fun(Rc::new(Function {
                    arity,
                    frame_size,
                    code: code.into(),
                }))
            }
            ParserValue::Object(entries) => {
                self.contexts.push(Context::new());

                let mut entries_compiled = FxHashMap::default();

                for (key, value) in entries {
                    let converted = self.convert_const(key);
                    let val = self.convert_const(value);

                    entries_compiled.insert(converted.get_hash(), val);
                }

                self.contexts.pop();

                Value::Object(Rc::new(RefCell::new(entries_compiled)))
            }
            ParserValue::EnumField { .. } => {
                unreachable!("EnumField is compiled directly and not via convert_const")
            }
        }
    }

    fn compile_enum_field(
        &mut self,
        name: String,
        tag: String,
        fields: Vec<Ast>,
    ) -> (usize, u8, Vec<(u64, u8)>) {
        let idx = self.enums.iter().position(|e| e.name == name);

        if idx.is_none() {
            self.error(
                0,
                0,
                format!("referencing enum definition that doesn't exist: '{}'", name),
            );
            return (0, 0, vec![]);
        }

        let enum_def = self.enums[idx.unwrap()].clone();

        let tag_idx = enum_def.variants.iter().position(|v| v.name == tag);

        if tag_idx.is_none() {
            self.error(
                0,
                0,
                format!(
                    "referencing enum field that doesn't exist: '{}::{}'",
                    name, tag
                ),
            );
            return (enum_def.idx, 0, vec![]);
        }

        let tag_info = enum_def.variants[tag_idx.unwrap()].clone();

        if tag_info.fields.len() != fields.len() {
            self.error(
                0,
                0,
                format!(
                    "expected {} values, got {} in {}::{}",
                    tag_info.fields.len(),
                    fields.len(),
                    name,
                    tag
                ),
            );
        }

        let mut arg_map = vec![];

        for (i, field) in fields.iter().enumerate() {
            let field_def = Rc::new(tag_info.fields[i].clone());

            let reg = self.compile(field.clone());
            arg_map.push((Value::String(field_def).get_hash(), reg));
        }

        (idx.unwrap(), tag_idx.unwrap() as u8, arg_map)
    }
}
