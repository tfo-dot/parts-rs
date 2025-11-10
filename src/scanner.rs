use crate::scanner_rules::ScannerRule;

#[derive(Debug)]
pub struct Scanner {
    rules: Vec<ScannerRule>,
    buffer: Vec<Token>,
    index: usize,
    source: String,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ScannerError {
    InvalidOperator(String),
    UnterminatedString,
    InvalidEscape,
    UnknownToken,
}

impl Scanner {
    pub fn new(rules: Vec<ScannerRule>, source: String) -> Self {
        Scanner {
            rules,
            buffer: vec![],
            index: 0,
            source,
        }
    }

    pub fn get_next(&mut self) -> Result<Token, ScannerError> {
        if let Some(elt) = self.buffer.pop() {
            return Ok(elt);
        }

        let ch = self.peek();

        if ch.is_none() {
            return Ok(Token(TokenType::Special, "EOF".chars().collect()));
        }

        for rule in &self.rules {
            if rule.base_rule.is_none() {
                if rule.valid_chars.contains(&self.peek().unwrap()) {
                    let res = Self::parse_rule(rule, &mut self.index, &self.source)?;

                    if rule.skip || res.iter().len() == 0 {
                        return self.get_next();
                    }

                    if res.len() == 1 {
                        return Ok(res[0].clone());
                    }

                    let return_token = res[0].clone();

                    self.buffer = res.clone().into_iter().skip(1).rev().collect();
                    return Ok(return_token);
                } else {
                    continue;
                }
            }

            if rule.base_rule.as_ref().unwrap()(&self.peek().unwrap()) {
                let res = Self::parse_rule(rule, &mut self.index, &self.source)?;

                if rule.skip || res.iter().len() == 0 {
                    return self.get_next();
                }

                if res.len() == 1 {
                    return Ok(res[0].clone());
                }

                let return_token = res[0].clone();

                self.buffer = res.clone().into_iter().skip(1).rev().collect();
                return Ok(return_token);
            }
        }

        if self.peek().is_none() {
            return Ok(Token(TokenType::Special, "EOF".chars().collect()));
        }

        Err(ScannerError::UnknownToken)
    }

    pub fn peek(&self) -> Option<char> {
        self.source.chars().nth(self.index)
    }

    pub fn parse_rule(
        rule: &ScannerRule,
        index: &mut usize,
        source: &str,
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

        Ok(vec![Token(
            rule.result.clone(),
            source[start..*index].chars().collect(),
        )])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(pub TokenType, pub Vec<char>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    Operator,
    Number,
    Keyword,
    Identifier,
    String,
    Space,
    Special,
}
