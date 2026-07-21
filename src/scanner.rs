use crate::scanner_rules::ScannerRule;

#[derive(Debug)]
pub struct Scanner {
    rules: Vec<ScannerRule>,
    buffer: Vec<Token>,
    index: usize,
    source: String,

    //Meta
    line: usize,
    column: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ScannerError {
    InvalidOperator(String),
    UnterminatedString,
    InvalidEscape,
    UnknownToken(char),
}

impl Scanner {
    pub fn new(rules: Vec<ScannerRule>, source: String) -> Self {
        Scanner {
            rules,
            buffer: vec![],
            index: 0,
            source,
            line: 1,
            column: 0,
        }
    }

    fn create_eof(&self) -> Token {
        return Token {
            kind: TokenType::Special,
            lexeme: "EOF".to_string(),
            span: Span {
                line: self.line,
                column: self.column,
            },
        };
    }

    pub fn get_next(&mut self) -> Result<Token, ScannerError> {
        if let Some(elt) = self.buffer.pop() {
            return Ok(elt);
        }

        let ch = self.peek();

        if ch.is_none() {
            return Ok(self.create_eof());
        }

        for rule in &self.rules {
            if rule.base_rule.is_none() {
                if rule.valid_chars.contains(&self.peek().unwrap()) {
                    let res = Self::parse_rule(rule, &mut self.index, &self.source, &mut self.line, &mut self.column)?;

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
                let res = Self::parse_rule(rule, &mut self.index, &self.source, &mut self.line, &mut self.column)?;

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
            return Ok(self.create_eof());
        }

        Err(ScannerError::UnknownToken(self.peek().unwrap()))
    }

    pub fn peek(&self) -> Option<char> {
        self.source.chars().nth(self.index)
    }

    pub fn parse_rule(
        rule: &ScannerRule,
        index: &mut usize,
        source: &str,
        line: &mut usize,
        column: &mut usize,
    ) -> Result<Vec<Token>, ScannerError> {
        let start = *index;

        let start_span = Span {
            line: *line,
            column: *column,
        };

        loop {
            *index += 1;

            let ch = source.chars().nth(*index);

            if let Some(c) = ch {
                if c == '\n' {
                    *line += 1;
                    *column = 0;
                } else {
                    *column += 1;
                }
            }

            let out_of_bounds = *index >= source.len();
            let no_base_but_valid =
                rule.base_rule.is_none() && rule.valid_chars.contains(&ch.unwrap_or('\x00'));
            let matches_base =
                rule.base_rule.is_some() && rule.base_rule.as_ref().unwrap()(&ch.unwrap_or('\x00'));
            let matches_whole =
                rule.rule.is_none() || rule.rule.as_ref().unwrap()(&source[start..*index]);

            if out_of_bounds || !(no_base_but_valid || matches_base) || !matches_whole {
                break;
            }
        }

        if rule.process.is_some() {
            return rule.process.as_ref().unwrap()(
                &rule.mappings,
                &source[start..*index],
                start_span,
            );
        }

        Ok(vec![Token {
            kind: rule.result.clone(),
            lexeme: source[start..*index].chars().collect(),
            span: start_span,
        }])
    }

    pub fn append_stream(&mut self, mut tokens: Vec<Token>) {
        tokens.reverse();
        self.buffer.splice(0..0, tokens);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenType,
    pub lexeme: String,
    pub span: Span,
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.lexeme == other.lexeme
    }
}

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
