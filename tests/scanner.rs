#[cfg(test)]
mod tests {
    use parts::scanner::Scanner;
    use parts::scanner::ScannerError;
    use parts::scanner::Token;
    use parts::scanner::TokenType;
    use parts::scanner_rules::ScannerRule;
    use std::collections::HashMap;

    #[test]
    fn check_operator() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "@".to_string());

        let at_token = s.get_next();

        assert!(at_token.is_ok());
        assert_eq!(
            at_token.as_ref().unwrap().to_owned(),
            Token(TokenType::Operator, vec!['A', 'T'])
        );

        let eof = s.get_next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::Special, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn check_operator_buffor() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "@+".to_string());

        let at_token = s.get_next();

        assert!(at_token.is_ok());
        assert_eq!(
            at_token.as_ref().unwrap().to_owned(),
            Token(TokenType::Operator, vec!['A', 'T'])
        );

        let plus_token = s.get_next();

        assert!(plus_token.is_ok());
        assert_eq!(
            plus_token.as_ref().unwrap().to_owned(),
            Token(TokenType::Operator, vec!['P', 'L', 'U', 'S'])
        );

        let eof = s.get_next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::Special, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn invalid_token() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "|".to_string());

        let at_token = s.get_next();

        assert!(at_token.is_err_and(|e| e == ScannerError::InvalidOperator("|".to_string())));
    }

    #[test]
    fn unknown_operator() {
        let mut s = Scanner::new(
            vec![ScannerRule {
                result: TokenType::Operator,
                base_rule: None,
                rule: None,
                process: Some(Box::new(|_mappings, _runs| Err(ScannerError::UnknownToken))),
                skip: false,
                mappings: HashMap::new(),
                valid_chars: vec![],
            }],
            "x".to_string(),
        );

        let at_token = s.get_next();

        assert!(at_token.is_err_and(|e| e == ScannerError::UnknownToken))
    }

    #[test]
    fn parse_number() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "1".to_string());

        let num_token = s.get_next();

        assert!(num_token.is_ok());
        assert_eq!(
            num_token.as_ref().unwrap().to_owned(),
            Token(TokenType::Number, vec!['1'])
        );
    }

    #[test]
    fn parse_decimal() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "3.14".to_string());

        let num_token = s.get_next();

        assert!(num_token.is_ok());
        assert_eq!(
            num_token.as_ref().unwrap().to_owned(),
            Token(TokenType::Number, "3.14".chars().collect::<Vec<char>>())
        );
    }

    #[test]

    fn parse_keyword() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "false".to_string());

        let false_token = s.get_next();

        assert!(false_token.is_ok());
        assert_eq!(
            false_token.as_ref().unwrap().to_owned(),
            Token(TokenType::Keyword, "FALSE".chars().collect::<Vec<char>>())
        );
    }

    #[test]
    fn parse_identifier() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "flse".to_string());

        let false_token = s.get_next();

        assert!(false_token.is_ok());
        assert_eq!(
            false_token.as_ref().unwrap().to_owned(),
            Token(TokenType::Identifier, "flse".chars().collect::<Vec<char>>())
        );
    }

    #[test]
    fn parse_space() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "  ".to_string());

        let eof = s.get_next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::Special, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn parse_string_tick() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "``".to_string());

        let string_token = s.get_next();

        assert!(string_token.is_ok());
        assert_eq!(
            string_token.as_ref().unwrap().to_owned(),
            Token(TokenType::String, vec![])
        );

        let eof = s.get_next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::Special, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn parse_string_normal() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "\"\"".to_string());

        let string_token = s.get_next();

        assert!(string_token.is_ok());
        assert_eq!(
            string_token.as_ref().unwrap().to_owned(),
            Token(TokenType::String, vec![])
        );

        let eof = s.get_next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::Special, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn parse_string_nested() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "\"``\"".to_string());

        let string_token = s.get_next();

        assert!(string_token.is_ok());
        assert_eq!(
            string_token.as_ref().unwrap().to_owned(),
            Token(TokenType::String, vec!['`', '`'])
        );

        let eof = s.get_next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::Special, vec!['E', 'O', 'F'])
        )
    }
}
