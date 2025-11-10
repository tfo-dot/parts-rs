use core::fmt::Result as FmtResult;
use core::fmt::{Debug, Formatter};
use std::collections::HashMap;

use crate::scanner::ScannerError;
use crate::scanner::{Token, TokenType};

type BaseRuleFn = Box<dyn Fn(&char) -> bool>;
type RuleFn = Box<dyn Fn(&str) -> bool>;
type ProcessFn = Box<dyn Fn(&HashMap<String, String>, &str) -> Result<Vec<Token>, ScannerError>>;

pub struct ScannerRule {
    pub(crate) result: TokenType,
    pub(crate) base_rule: Option<BaseRuleFn>,
    pub(crate) rule: Option<RuleFn>,
    pub(crate) process: Option<ProcessFn>,
    pub(crate) skip: bool,
    pub(crate) mappings: HashMap<String, String>,
    pub(crate) valid_chars: Vec<char>,
}

impl Debug for ScannerRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ScannerRule")
            .field("result", &self.result)
            .field("base_rule_exists", &self.base_rule.is_some())
            .field("rule_exists", &self.rule.is_some())
            .field("process_exists", &self.process.is_some())
            .field("skip", &self.skip)
            .field("mappings", &self.mappings)
            .field("valid_chars", &self.valid_chars)
            .finish()
    }
}

//TODO str.len() returns bytes count, str.chars() method chars, for example 0xa0 counts as 2 bytes, but one char making test fail if passed

impl ScannerRule {
    pub fn get_default_rules() -> Vec<ScannerRule> {
        vec![
            ScannerRule {
                result: TokenType::Operator,
                base_rule: None,
                rule: None,
                process: Some(Box::new(|mappings, runs| {
                    let token_value: String = runs.chars().collect();

                    if let Some(name) = mappings.get(&token_value) {
                        return Ok(vec![Token(TokenType::Operator, name.chars().collect())]);
                    }

                    let mut ret_tokens = Vec::new();
                    let mut offset = 0;
                    let mut temp_slice = &token_value[..];

                    while offset != token_value.len() {
                        if temp_slice.is_empty() {
                            return Err(ScannerError::InvalidOperator(
                                token_value[offset..].to_string(),
                            ));
                        }

                        if let Some(name) = mappings.get(temp_slice) {
                            offset += temp_slice.len();
                            ret_tokens.push(Token(TokenType::Operator, name.chars().collect()));
                            temp_slice = &token_value[offset..];
                        } else {
                            temp_slice = &temp_slice[..temp_slice.len() - 1];
                        }
                    }

                    Ok(ret_tokens)
                })),
                skip: false,
                mappings: [
                    ("+", "PLUS"),
                    ("-", "MINUS"),
                    ("/", "SLASH"),
                    ("*", "STAR"),
                    ("%", "MOD"),
                    (";", "SEMICOLON"),
                    (":", "COLON"),
                    (".", "DOT"),
                    (",", "COMMA"),
                    ("(", "LEFT_PAREN"),
                    (")", "RIGHT_PAREN"),
                    ("{", "LEFT_BRACE"),
                    ("}", "RIGHT_BRACE"),
                    ("[", "LEFT_BRACKET"),
                    ("]", "RIGHT_BRACKET"),
                    ("@", "AT"),
                    ("=", "EQUALS"),
                    ("|>", "OBJ_START"),
                    ("<|", "OBJ_END"),
                    ("==", "EQUALITY"),
                    ("<", "LESS_THAN"),
                    (">", "MORE_THAN"),
                    ("<=", "LESS_EQ"),
                    (">=", "MORE_EQ"),
                ]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
                valid_chars: vec![
                    '+', '-', '/', '*', ';', '[', ']', '(', ')', '{', '}', '.', ':', ',', '|', '&',
                    '>', '<', '!', '#', '-', '=', '?', '%', '@',
                ],
            }, // --- TokenNumber Rule ---
            ScannerRule {
                result: TokenType::Number,
                base_rule: Some(Box::new(|r| *r >= '0' && *r <= '9')),
                rule: None,
                process: None,
                skip: false,
                mappings: HashMap::new(),
                valid_chars: vec![],
            },
            // --- TokenKeyword Rule ---
            ScannerRule {
                result: TokenType::Keyword,
                base_rule: Some(Box::new(|r| {
                    (*r >= 'a' && *r <= 'z') || (*r >= 'A' && *r <= 'Z') || *r == '_'
                })),
                rule: None,
                process: Some(Box::new(|mappings, runs| {
                    let mut token = Token(TokenType::Keyword, runs.chars().collect());
                    let value_str: String = token.1.iter().collect();

                    if mappings.contains_key(&value_str) {
                        token.1 = value_str.to_uppercase().chars().collect();
                    } else {
                        token.0 = TokenType::Identifier;
                    }

                    Ok(vec![token])
                })),
                skip: false,
                mappings: [
                    ("false", ""),
                    ("if", ""),
                    ("let", ""),
                    ("true", ""),
                    ("fun", ""),
                    ("return", ""),
                    ("else", ""),
                    ("for", ""),
                    ("import", ""),
                    ("from", ""),
                    ("as", ""),
                    ("syntax", ""),
                    ("use", ""),
                    ("raise", ""),
                    ("break", ""),
                    ("continue", ""),
                    ("translation", ""),
                ]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
                valid_chars: vec![],
            },
            // --- TokenSpace Rule ---
            ScannerRule {
                result: TokenType::Space,
                base_rule: Some(Box::new(|r| r.is_whitespace())),
                rule: None,
                process: None,
                skip: true,
                mappings: HashMap::new(),
                valid_chars: vec![],
            },
            // --- TokenString Rule ---
            ScannerRule {
                result: TokenType::String,
                base_rule: Some(Box::new(|_r| true)),
                rule: Some(Box::new(|runs| {
                    runs.len() == 1
                        || runs.chars().collect::<Vec<_>>().first()
                            != runs.chars().collect::<Vec<_>>().last()
                })),
                process: Some(Box::new(|_mappings, runs| {
                    if runs.len() < 2 {
                        return Err(ScannerError::UnterminatedString);
                    }

                    let left_side = runs.chars().nth(0).unwrap();
                    let right_side = runs.chars().nth(runs.len() - 1).unwrap();

                    if left_side == '"' && right_side != '"' {
                        return Err(ScannerError::UnterminatedString);
                    }
                    
                    if left_side == '`' && right_side != '`' {
                        return Err(ScannerError::UnterminatedString);
                    }

                    if left_side != '"' && left_side != '`' {
                        return Err(ScannerError::UnknownToken);
                    }
                    
                    // Get the content inside the quotes
                    let content = &runs[1..runs.len() - 1];
                    let mut unescaped = Vec::new();
                    let mut i = 0;

                    while i < content.len() {
                        if content.chars().nth(i).unwrap() == '\\' {
                            if i + 1 >= content.len() {
                                return Err(ScannerError::InvalidEscape);
                            }
                            // Handle escape sequences
                            match content.chars().nth(i + 1).unwrap() {
                                '"' => unescaped.push('"'),
                                '\\' => unescaped.push('\\'),
                                'n' => unescaped.push('\n'),
                                't' => unescaped.push('\t'),
                                'r' => unescaped.push('\r'),
                                'b' => unescaped.push('\x08'), // Backspace
                                'f' => unescaped.push('\x0C'), // Formfeed
                                _other => {
                                    return Err(ScannerError::InvalidEscape);
                                }
                            }
                            i += 2; // Skip \ and the escaped char
                        } else {
                            unescaped.push(content.chars().nth(i).unwrap());
                            i += 1; // Skip this char
                        }
                    }

                    Ok(vec![Token(TokenType::String, unescaped)])
                })),
                skip: false,
                mappings: HashMap::new(),
                valid_chars: vec![],
            },
        ]
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    use crate::scanner::{Scanner};

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