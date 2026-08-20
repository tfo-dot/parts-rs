#[cfg(test)]
mod tests {
    use parts::engine::Engine;
    use parts::value::Value;

    #[test]
    fn test_basic_enum() {
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power),
                South(power)
            }
            let d = Direction::North(100.0);
            return d.power;
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(100.0)));
    }

    #[test]
    fn test_enum_in_function_scope_high_register_index() {
        // Inside a function call, fp = 256. The registers on VM stack have index >= 256.
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power),
                South(power)
            }
            let get_power() {
                let d = Direction::North(42.0);
                return d.power;
            }
            return get_power();
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(42.0)));
    }

    #[test]
    fn test_enum_returned_from_function_crossing_scope() {
        // Function creates enum and returns it. Caller accesses field after callee frame popped.
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power),
                South(power)
            }
            let make_dir(p) {
                let d = Direction::North(p);
                return d;
            }
            let d = make_dir(77.5);
            return d.power;
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(77.5)));
    }

    #[test]
    fn test_enum_passed_to_function_crossing_scope() {
        // Caller creates enum and passes to function. Callee accesses field at fp = 256.
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power),
                South(power)
            }
            let extract_power(d) {
                return d.power;
            }
            let d = Direction::North(88.0);
            return extract_power(d);
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(88.0)));
    }

    #[test]
    fn test_enum_multi_level_function_calls() {
        // Deep call stack: fp = 0 -> 256 -> 512 -> 768.
        let engine = Engine::new();
        let source = "
            enum Point {
                Pt(x, y)
            }
            let create_point(x, y) {
                return Point::Pt(x, y);
            }
            let transform(pt) {
                let new_pt = create_point(pt.x + 10, pt.y + 20);
                return new_pt;
            }
            let compute(pt) {
                let t = transform(pt);
                return (t.x * 100) + t.y;
            }
            let origin = Point::Pt(5, 7);
            return compute(origin);
        ";
        let result = engine.execute(source).unwrap();
        // origin = Pt(5, 7), transformed = Pt(15, 27), compute = (15 * 100) + 27 = 1527
        assert_eq!(result, Some(Value::Int(1527)));
    }

    #[test]
    fn test_enum_direct_return() {
        let engine = Engine::new();
        let source = "
            enum Result {
                Ok(val),
                Err(msg)
            }
            let make_ok() {
                return Result::Ok(12345);
            }
            let r = make_ok();
            return r.val;
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Int(12345)));
    }

    #[test]
    fn test_enum_direct_argument() {
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power)
            }
            let get_power(d) {
                return d.power;
            }
            return get_power(Direction::North(99.0));
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(99.0)));
    }

    #[test]
    fn test_enum_assignment_set() {
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power)
            }
            let d = 0;
            d = Direction::North(333.0);
            return d.power;
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(333.0)));
    }

    #[test]
    fn test_enum_block_scope_register_reuse() {
        // Enums created in nested block where registers are reused afterwards.
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power)
            }
            let d = 0;
            {
                let temp = 100.0 + 50.0;
                d = Direction::North(temp);
            }
            let filler_a = 999.0;
            let filler_b = 888.0;
            return d.power;
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(150.0)));
    }

    #[test]
    fn test_enum_with_complex_expression_fields() {
        let engine = Engine::new();
        let source = "
            enum Point {
                Pt(x, y)
            }
            let a = 10;
            let b = 20;
            let p = Point::Pt((a * 2) + 5, (b * 3) - 2);
            let next_var = 9999;
            return p.x + p.y;
        ";
        let result = engine.execute(source).unwrap();
        // x = 25, y = 58, sum = 83
        assert_eq!(result, Some(Value::Int(83)));
    }

    #[test]
    fn test_enum_unit_variants() {
        let engine = Engine::new();
        let source = "
            enum Status {
                Active,
                Inactive
            }
            let status_a = Status::Active;
            let status_b = Status::Inactive;
            let status_c = Status::Active;
            if (status_a == status_c) & ((status_a == status_b) == false) {
                return 1;
            } else {
                return 0;
            }
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Int(1)));
    }

    #[test]
    fn test_enum_equality_across_scopes() {
        let engine = Engine::new();
        let source = "
            enum Msg {
                Text(content),
                Code(num)
            }
            let make_msg_a() {
                return Msg::Text(\"hello\");
            }
            let make_msg_b() {
                return Msg::Text(\"hello\");
            }
            let make_msg_c() {
                return Msg::Text(\"world\");
            }
            let make_msg_d() {
                return Msg::Code(123);
            }
            let m_a = make_msg_a();
            let m_b = make_msg_b();
            let m_c = make_msg_c();
            let m_d = make_msg_d();
            if (m_a == m_b) & ((m_a == m_c) == false) & ((m_a == m_d) == false) {
                return 1;
            } else {
                return 0;
            }
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Int(1)));
    }

    #[test]
    fn test_enum_with_if_control_flow_jump_offset() {
        // Verifies byte length calculation for LoadEnumField in jump offsets.
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power),
                South(power)
            }
            let check(p) {
                let d = Direction::North(p);
                if d.power > 50.0 {
                    return 1;
                } else {
                    return 2;
                }
            }
            return (check(100.0) * 10) + check(10.0);
        ";
        let result = engine.execute(source).unwrap();
        // check(100.0) = 1, check(10.0) = 2 -> 1 * 10 + 2 = 12
        assert_eq!(result, Some(Value::Int(12)));
    }

    #[test]
    fn test_enum_in_loop() {
        let engine = Engine::new();
        let source = "
            enum Item {
                Val(num)
            }
            let sum = 0;
            let i = 0;
            for i < 5 {
                let item = Item::Val(i * 10);
                sum = sum + item.num;
                i = i + 1;
            }
            return sum;
        ";
        let result = engine.execute(source).unwrap();
        // 0 + 10 + 20 + 30 + 40 = 100
        assert_eq!(result, Some(Value::Int(100)));
    }

    #[test]
    fn test_enum_in_object() {
        let engine = Engine::new();
        let source = "
            enum Direction {
                North(power)
            }
            let obj = |>
                dir: Direction::North(123.4)
            <|;
            let get_obj_power(o) {
                return o.dir.power;
            }
            return get_obj_power(obj);
        ";
        let result = engine.execute(source).unwrap();
        assert_eq!(result, Some(Value::Double(123.4)));
    }

    #[test]
    fn test_enum_many_registers_before_enum() {
        // Allocates many local variables (registers) before creating and using enums.
        let engine = Engine::new();
        let mut source = String::from("
            enum Direction {
                North(power)
            }
            let run() {
        ");
        for i in 0..50 {
            // Generate variable names like va, vb, vc, ..., vba, vbb, ...
            let name = format!("v_{}_{}", (b'a' + (i % 26) as u8) as char, (b'a' + (i / 26) as u8) as char);
            source.push_str(&format!("let {} = {};\n", name, i));
        }
        source.push_str("
                let d = Direction::North(777.0);
                return d.power;
            }
            return run();
        ");
        let result = engine.execute(&source).unwrap();
        assert_eq!(result, Some(Value::Double(777.0)));
    }

    #[test]
    fn test_enum_display_and_serialization() {
        use std::rc::Rc;
        let val = Value::EnumField {
            const_idx: 0,
            tag: 1,
            args: vec![
                (12345, Value::Int(42)),
                (67890, Value::String(Rc::new("test".to_string()))),
            ],
        };

        // Display test
        let formatted = format!("{}", val);
        assert!(formatted.contains("EnumField(0, tag: 1"));
        assert!(formatted.contains("42"));
        assert!(formatted.contains("test"));

        // Serialization roundtrip
        let mut buffer = Vec::new();
        val.encode(&mut buffer);

        let (decoded, _) = Value::decode(&buffer, true, 0);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], val);
    }
}
