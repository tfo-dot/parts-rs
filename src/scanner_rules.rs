use core::fmt::Result as FmtResult;
use core::fmt::{Debug, Formatter};
use std::collections::HashMap;

use crate::scanner::ScannerError;
use crate::scanner::{Token, TokenType};

type BaseRuleFn = Box<dyn Fn(&char) -> bool>;
type RuleFn = Box<dyn Fn(&str) -> bool>;
type ProcessFn = Box<dyn Fn(&HashMap<String, String>, &str) -> Result<Vec<Token>, ScannerError>>;

pub struct ScannerRule {
    pub result: TokenType,
    pub base_rule: Option<BaseRuleFn>,
    pub rule: Option<RuleFn>,
    pub process: Option<ProcessFn>,
    pub skip: bool,
    pub mappings: HashMap<String, String>,
    pub valid_chars: Vec<char>,
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

//TODO str.len() returns bytes count, str.chars() - chars, for example 0xa0 counts as 2 bytes, but one char is making test fail if passed in a string

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
                    ("!", "BANG"),
                    ("=", "EQUALS"),
                    ("|>", "OBJ_START"),
                    ("<|", "OBJ_END"),
                    ("==", "EQUALITY"),
                    ("<", "LESS_THAN"),
                    (">", "MORE_THAN"),
                    ("<=", "LESS_EQ"),
                    (">=", "MORE_EQ"),
                    ("=>", "ARROW_LEFT")
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
                base_rule: Some(Box::new(|r| *r >= '0' && *r <= '9' || *r == '.')),
                rule: Some(Box::new(|r| r.chars().filter(|&c| c == '.').count() <= 1)),
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
                    ("in", ""),
                    ("part", "")
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
