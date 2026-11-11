use parts::compiler::{Compiler, IrOp};
use parts::engine::Engine;
use parts::optimize::{AstOptimizer, IrOptimizer};
use parts::parser::Parser;
use parts::tools::LanguageTools;
use parts::value::Value;

#[test]
fn test_std_static_resolution_avoids_get_property_and_ws() {
    let source = r#"
        let std = import `@std/std.pts`;
        let m = std.math;
        let x = std.math.sin(0.0) + m.cos(0.0);
        return x;
    "#;
    let mut parser = Parser::new(source.to_string());
    let ast = parser.parse_all().unwrap();
    let mut compiler = Compiler::new("./".into());
    compiler.optimize = true;
    let ir = compiler.compile_all(ast).unwrap();

    assert!(
        ir.iter().any(|op| matches!(op, IrOp::CallNative { .. })),
        "expected static std.math calls to lower to CallNative"
    );
    assert!(
        !ir.iter().any(|op| matches!(op, IrOp::GetProperty { .. } | IrOp::LoadStdModule { .. })),
        "expected no runtime GetProperty or LoadStdModule when std does not escape"
    );
    assert!(
        compiler.constant_pool.len() <= 4,
        "expected minimal constant pool without ws.pts, got {} entries",
        compiler.constant_pool.len()
    );

    let engine = Engine::new();
    let res = engine.execute(source).unwrap();
    assert_eq!(res, Some(Value::Double(1.0)));
}

#[test]
fn test_std_parts_written_functions_math_abs_and_bytes_pad() {
    let engine = Engine::new();
    let source = r#"
        let std = import `@std/std.pts`;
        let a = std.math.abs(0 - 42);
        let b = std.math.abs(17);
        let m = std.math;
        let c = m.abs(0 - 5);
        let buf = std.bytes.new(3).unwrap();
        std.bytes.pad(buf, 8);
        return a + b + c + buf.len();
    "#;
    let res = engine.execute(source).unwrap();
    assert_eq!(res, Some(Value::Int(42 + 17 + 5 + 8)));
}

#[test]
fn test_std_direct_submodule_paths_and_destructured_import() {
    let engine = Engine::new();
    let source = r#"
        let math_short = import `@std/math.pts`;
        let math_full = import `@std/std/math.pts`;
        import { floor, abs, PI } from `@std/math.pts`;
        import { upper } from `@std/str.pts`;
        let s = upper("ok");
        if (s == "OK") == false {
            return 0;
        }
        return math_short.floor(PI) + math_full.abs(0 - 7) + floor(PI) + abs(0 - 2);
    "#;
    let res = engine.execute(source).unwrap();
    assert_eq!(res, Some(Value::Int(3 + 7 + 3 + 2)));
}

#[test]
fn test_std_escape_to_function_materializes_lazily_and_includes_overlays() {
    let engine = Engine::new();
    let source = r#"
        let std = import `@std/std.pts`;
        let call_abs(mod_obj, v) {
            return mod_obj.abs(v);
        }
        let call_sin_via_root(root_std) {
            return root_std.math.cos(0.0);
        }
        let dyn_key = "bytes";
        let b = std[dyn_key].new(5).unwrap();
        std[dyn_key].pad(b, 8);
        return call_abs(std.math, 0 - 11) + call_sin_via_root(std) + b.len();
    "#;
    let res = engine.execute(source).unwrap();
    assert_eq!(res, Some(Value::Double(11.0 + 1.0 + 8.0)));
}

#[test]
fn test_std_shadowing_and_reassignment_remain_sound() {
    let engine = Engine::new();
    let source = r#"
        let std = import `@std/std.pts`;
        let inner_shadow(x) {
            let std = |> math: |> cos: fun(v) = 100 <| <|;
            return std.math.cos(x);
        }
        let outer_before = std.math.cos(0.0);
        let shadowed = inner_shadow(0.0);
        let outer_after = std.math.cos(0.0);

        let local_std = import `@std/std.pts`;
        local_std = |> math: |> floor: fun(v) = 77 <| <|;
        let reassigned = local_std.math.floor(1.5);

        return outer_before + shadowed + outer_after + reassigned;
    "#;
    let res = engine.execute(source).unwrap();
    assert_eq!(res, Some(Value::Double(1.0 + 100.0 + 1.0 + 77.0)));
}

#[test]
fn test_std_monkey_patch_shared_alias_consistency() {
    let engine = Engine::new();
    let source = r#"
        let std = import `@std/std.pts`;
        let m = std.math;
        m.floor = fun(v) = 55;
        return std.math.floor(1.9) + m.floor(2.9);
    "#;
    let res = engine.execute(source).unwrap();
    assert_eq!(res, Some(Value::Int(110)));
}

#[test]
fn test_std_unknown_module_reports_compiler_error_instead_of_panicking() {
    let report = LanguageTools::check("let bad = import `@std/does_not_exist.pts`;", None);
    assert!(report.has_errors());
}

#[test]
fn test_std_call_native_and_load_std_module_ptc_roundtrip() {
    let source = r#"
        let std = import `@std/std.pts`;
        let pass_through(s) {
            return s.math.floor(s.math.PI) + s.math.abs(0 - 4);
        }
        return pass_through(std) + std.math.floor(std.math.PI);
    "#;
    let mut parser = Parser::new(source.to_string());
    let mut ast = parser.parse_all().unwrap();
    let mut opt = AstOptimizer::new();
    opt.collect_all(&ast);
    while opt.optimize_all(&mut ast) {}

    let mut compiler = Compiler::new("./".into());
    compiler.optimize = true;
    let ir = IrOptimizer::optimize(compiler.compile_all(ast).unwrap());
    let bc = parts::emitter::Emitter {}.emit(ir);

    let mut encoded = Vec::new();
    for c in &compiler.constant_pool {
        c.encode(&mut encoded);
    }
    let (decoded_consts, _) = Value::decode(&encoded, false, 0);

    let mut vm = parts::vm::VM::new(bc, decoded_consts);
    let out = vm.run().unwrap();
    assert_eq!(out, Some(Value::Int(3 + 4 + 3)));
}

#[test]
fn test_std_nested_function_accesses_top_level_alias_and_escapes() {
    let engine = Engine::new();
    let source = r#"
        let std = import `@std/std.pts`;
        let get_root() {
            return std;
        }
        let use_sin() {
            return std.math.cos(0.0);
        }
        return get_root().math.floor(std.math.PI) + use_sin();
    "#;
    let res = engine.execute(source).unwrap();
    assert_eq!(res, Some(Value::Double(4.0)));
}
