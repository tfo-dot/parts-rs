use crate::scanner_rules::ScannerRule;

#[derive(Debug)]
pub struct Scanner {
    rules: Vec<ScannerRule>,
    buffer: Vec<Token>,
    index: usize,
    source: String,
}

#[derive(Debug, PartialEq)]
pub enum ScannerError {
    InvalidOperator(String),
    UnterminatedString,
    InvalidEscape,
    UnknownToken,
}

impl Scanner {
    fn new(rules: Vec<ScannerRule>, source: String) -> Self {
        return Scanner {
            rules,
            buffer: vec![],
            index: 0,
            source,
        };
    }

    fn next(&mut self) -> Result<Token, ScannerError> {
        if let Some(elt) = self.buffer.pop() {
            return Ok(elt);
        }

        let ch = self.peek();

        if ch.is_none() {
            return Ok(Token(TokenType::TokenSpecial, "EOF".chars().collect()));
        }

        for rule in &self.rules {
            if rule.base_rule.is_none() {
                if rule.valid_chars.contains(&self.peek().unwrap()) {
                    let res = Self::parse_rule(&rule, &mut self.index, &self.source);

                    if res.is_err() {
                        return Err(res.unwrap_err());
                    }

                    let return_value = res.unwrap();

                    if rule.skip || return_value.iter().len() == 0 {
                        return self.next();
                    }

                    if return_value.len() == 1 {
                        return Ok(return_value[0].clone());
                    }

                    let return_token = return_value[0].clone();

                    self.buffer = return_value.clone().into_iter().skip(1).rev().collect();
                    return Ok(return_token);
                } else {
                    continue;
                }
            }

            if rule.base_rule.as_ref().unwrap()(&self.peek().unwrap()) {
                let res = Self::parse_rule(&rule, &mut self.index, &self.source);

                if res.is_err() {
                    return Err(res.unwrap_err());
                }

                let return_value = res.unwrap();

                if rule.skip || return_value.iter().len() == 0 {
                    return self.next();
                }

                if return_value.len() == 1 {
                    return Ok(return_value[0].clone());
                }

                let return_token = return_value[0].clone();

                self.buffer = return_value.clone().into_iter().skip(1).rev().collect();
                return Ok(return_token);
            }
        }

        if self.peek().is_none() {
            return Ok(Token(TokenType::TokenSpecial, "EOF".chars().collect()));
        }

        Err(ScannerError::UnknownToken)
    }

    fn peek(&self) -> Option<char> {
        return self.source.chars().nth(self.index);
    }

    fn parse_rule(
        rule: &ScannerRule,
        index: &mut usize,
        source: &String,
    ) -> Result<Vec<Token>, ScannerError> {
        let start = *index;

        loop {
            *index += 1;

            let out_of_bounds = *index >= source.len();
            let no_base_but_valid = rule.base_rule.is_none()
                && rule
                    .valid_chars
                    .contains(&source.chars().nth(*index).unwrap_or('\x00'));
            let matches_base = rule.base_rule.is_some()
                && rule.base_rule.as_ref().unwrap()(&source.chars().nth(*index).unwrap_or('\x00'));
            let matches_whole =
                rule.rule.is_none() || rule.rule.as_ref().unwrap()(&source[start..*index]);

            if out_of_bounds || !(no_base_but_valid || matches_base) || !matches_whole {
                break;
            }
        }

        if rule.process.is_some() {
            return rule.process.as_ref().unwrap()(&rule.mappings, &source[start..*index]);
        }

        return Ok(vec![Token(
            rule.result.clone(),
            source[start..*index].chars().collect(),
        )]);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(pub TokenType, pub Vec<char>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    TokenOperator,
    TokenNumber,
    TokenKeyword,
    TokenIdentifier,
    TokenString,
    TokenSpace,
    TokenSpecial,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn check_operator() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "@".to_string());

        let at_token = s.next();

        assert!(at_token.is_ok());
        assert_eq!(
            at_token.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenOperator, vec!['A', 'T'])
        );

        let eof = s.next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenSpecial, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn check_operator_buffor() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "@+".to_string());

        let at_token = s.next();

        assert!(at_token.is_ok());
        assert_eq!(
            at_token.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenOperator, vec!['A', 'T'])
        );

        let plus_token = s.next();

        assert!(plus_token.is_ok());
        assert_eq!(
            plus_token.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenOperator, vec!['P', 'L', 'U', 'S'])
        );

        let eof = s.next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenSpecial, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn invalid_token() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "|".to_string());

        let at_token = s.next();

        assert!(at_token.is_err_and(|e| e == ScannerError::InvalidOperator("|".to_string())));
    }

    #[test]
    fn unknown_operator() {
        let mut s = Scanner::new(
            vec![ScannerRule {
                result: TokenType::TokenOperator,
                base_rule: None,
                rule: None,
                process: Some(Box::new(|_mappings, _runs| Err(ScannerError::UnknownToken))),
                skip: false,
                mappings: HashMap::new(),
                valid_chars: vec![],
            }],
            "x".to_string(),
        );

        let at_token = s.next();

        assert!(at_token.is_err_and(|e| e == ScannerError::UnknownToken))
    }

    #[test]
    fn parse_number() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "1".to_string());

        let num_token = s.next();

        assert!(num_token.is_ok());
        assert_eq!(
            num_token.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenNumber, vec!['1'])
        );
    }

    #[test]

    fn parse_keyword() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "false".to_string());

        let false_token = s.next();

        assert!(false_token.is_ok());
        assert_eq!(
            false_token.as_ref().unwrap().to_owned(),
            Token(
                TokenType::TokenKeyword,
                "FALSE".chars().collect::<Vec<char>>()
            )
        );
    }

    #[test]
    fn parse_identifier() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "flse".to_string());

        let false_token = s.next();

        assert!(false_token.is_ok());
        assert_eq!(
            false_token.as_ref().unwrap().to_owned(),
            Token(
                TokenType::TokenIdentifier,
                "flse".chars().collect::<Vec<char>>()
            )
        );
    }

    #[test]
    fn parse_space() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "  ".to_string());

        let eof = s.next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenSpecial, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn parse_string_tick() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "``".to_string());

        let string_token = s.next();

        assert!(string_token.is_ok());
        assert_eq!(
            string_token.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenString, vec![])
        );

        let eof = s.next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenSpecial, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn parse_string_normal() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "\"\"".to_string());

        let string_token = s.next();

        assert!(string_token.is_ok());
        assert_eq!(
            string_token.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenString, vec![])
        );

        let eof = s.next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenSpecial, vec!['E', 'O', 'F'])
        )
    }

    #[test]
    fn parse_string_nested() {
        let mut s = Scanner::new(ScannerRule::get_default_rules(), "\"``\"".to_string());

        let string_token = s.next();

        assert!(string_token.is_ok());
        assert_eq!(
            string_token.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenString, vec!['`', '`'])
        );

        let eof = s.next();

        assert!(eof.is_ok());
        assert_eq!(
            eof.as_ref().unwrap().to_owned(),
            Token(TokenType::TokenSpecial, vec!['E', 'O', 'F'])
        )
    }
}
