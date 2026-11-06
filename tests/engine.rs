#[cfg(test)]
mod tests {
    use parts::engine::Engine;
    use parts::value::Value;

    #[test]
    fn test_execute() {
        let engine = Engine::new();
        let result = engine.execute("return 1 + 2;").unwrap();
        assert_eq!(result, Some(Value::Int(3)));
    }

    #[test]
    fn test_iterative() {
        let engine = Engine::new();
        let source = "
            let a = 0;
            let b = 1;
            let i = 0;
            for i < 10 {
                let temp = a + b;
                a = b;
                b = temp;
                i = i + 1;
            }
            return a;
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Int(55)));
    }

    #[test]
    fn test_call_function() {
        let engine = Engine::new();
        let source = "
            let add(a, b) = {
                return a + b;
            }
            return add;
        ";
        let res = engine.run(source).unwrap();
        let func = res.value.unwrap();

        let call_res = func
            .call(vec![Value::Int(10), Value::Int(20)], res.constants)
            .unwrap();

        assert_eq!(call_res, Some(Value::Int(30)));
    }

    #[test]
    fn test_custom_native() {
        let mut engine = Engine::new();
        engine.register_native("rust_add", 2, |args| match (&args[0], &args[1]) {
            (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a + b)),
            _ => Err("Expected two integers".to_string()),
        });

        let source = "return rust_add(5, 7);";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Int(12)));
    }

    #[test]
    fn test_persistent_module_instance_state_mutation() {
        let engine = Engine::new();
        let source = "
            let count = 0;
            let helper_bump() {
                count = count + 10;
                return count;
            }

            return |>
                on_tick: fun() {
                    return helper_bump();
                },
                get_count: fun() {
                    return count;
                }
            <|;
        ";
        let mut instance = engine.instantiate(source).unwrap();
        assert!(instance.has_method("on_tick"));
        assert!(instance.has_method("get_count"));

        let res1 = instance.call_method("on_tick", vec![]).unwrap();
        assert_eq!(res1, Some(Value::Int(10)));

        let res2 = instance.call_method("on_tick", vec![]).unwrap();
        assert_eq!(res2, Some(Value::Int(20)));

        let res3 = instance.call_method("on_tick", vec![]).unwrap();
        assert_eq!(res3, Some(Value::Int(30)));

        let count_val = instance.call_method("get_count", vec![]).unwrap();
        assert_eq!(count_val, Some(Value::Int(30)));
    }

    #[test]
    fn test_logical_operators_short_circuit() {
        let mut engine = Engine::new();
        let side_effects = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let se = side_effects.clone();
        engine.register_native("trigger_side_effect", 0, move |_| {
            se.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Value::Bool(true))
        });

        // false && trigger_side_effect() -> RHS not evaluated
        let res = engine
            .execute("return false && trigger_side_effect();")
            .unwrap();
        assert_eq!(res, Some(Value::Bool(false)));
        assert_eq!(side_effects.load(std::sync::atomic::Ordering::SeqCst), 0);

        // true && trigger_side_effect() -> RHS evaluated
        let res = engine
            .execute("return true && trigger_side_effect();")
            .unwrap();
        assert_eq!(res, Some(Value::Bool(true)));
        assert_eq!(side_effects.load(std::sync::atomic::Ordering::SeqCst), 1);

        // true || trigger_side_effect() -> RHS not evaluated
        let res = engine
            .execute("return true || trigger_side_effect();")
            .unwrap();
        assert_eq!(res, Some(Value::Bool(true)));
        assert_eq!(side_effects.load(std::sync::atomic::Ordering::SeqCst), 1);

        // false || trigger_side_effect() -> RHS evaluated
        let res = engine
            .execute("return false || trigger_side_effect();")
            .unwrap();
        assert_eq!(res, Some(Value::Bool(true)));
        assert_eq!(side_effects.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn test_large_u64_integer_constants() {
        let engine = Engine::new();
        // 2^63 = 9223372036854775808
        let source = "
            let x = 9223372036854775808;
            return x == 9223372036854775808;
        ";
        let res = engine.execute(source).unwrap();
        assert_eq!(res, Some(Value::Bool(true)));
    }

    #[test]
    fn test_register_allocator_pressure_in_loops() {
        let engine = Engine::new();
        // A loop with complex expressions that would overflow a u8 if registers were not recycled
        let source = "
            let sum = 0;
            let i = 0;
            for i < 100 {
                let a = i + 1;
                let b = a * 2;
                let c = b + 3;
                let d = c - 4;
                sum = sum + d;
                i = i + 1;
            }
            return sum;
        ";
        let res = engine.execute(source).unwrap();
        // d = ((i + 1) * 2 + 3) - 4 = 2*i + 1
        // sum = sum_{i=0..99} (2i + 1) = 100^2 = 10000
        assert_eq!(res, Some(Value::Int(10000)));
    }

    #[test]
    fn test_unwrap_on_raw_values() {
        let engine = Engine::new();
        // Calling unwrap() on raw strings, ints, etc. should not panic
        let source = r#"
            let s = "hello".unwrap();
            let x = 42;
            let n = x.unwrap();
            return s.join(" world");
        "#;
        let res = engine.execute(source).unwrap();
        assert_eq!(res, Some(Value::String("hello world".to_string().into())));
    }

    #[test]
    fn test_source_map_location_reporting() {
        let engine = Engine::new();
        let source = "let a = 1;\nlet b = 2;\nreturn a + b;\n";
        let res = engine.run(source).unwrap();
        assert!(res.instance.is_some());
        let inst = res.instance.unwrap();
        assert!(inst.vm.source_map.is_some());
    }

    #[test]
    fn test_sleep_native() {
        let engine = Engine::new();
        let source = r#"
            let std = import `@std/std.pts`;
            std.sleep(1);
            return 1;
        "#;
        let res = engine.execute(source).unwrap();
        assert_eq!(res, Some(Value::Int(1)));
    }
}
