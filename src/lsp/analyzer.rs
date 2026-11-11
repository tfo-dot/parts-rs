use std::path::{Path, PathBuf};

use crate::{
    diagnostic::DiagnosticLevel,
    lsp::protocol::{
        CompletionItem, CompletionItemKind, Diagnostic, DiagnosticSeverity, DocumentSymbol, Hover,
        InsertTextFormat, Location, MarkupContent, Position, Range, SymbolKind, TextEdit,
    },
    parser::{Ast, Parser, Value as ParserValue},
    scanner::{Scanner, TokenType},
    scanner_rules::ScannerRule,
    tools::LanguageTools,
};

#[derive(Debug, Clone)]
pub struct Document {
    pub uri: String,
    pub version: i32,
    pub text: String,
    pub lines: Vec<String>,
}

impl Document {
    pub fn new(uri: String, version: i32, text: String) -> Self {
        let lines = text.lines().map(|s| s.to_string()).collect();
        Self {
            uri,
            version,
            text,
            lines,
        }
    }

    pub fn update(&mut self, version: i32, text: String) {
        self.version = version;
        self.lines = text.lines().map(|s| s.to_string()).collect();
        self.text = text;
    }

    pub fn get_import_path(&self) -> PathBuf {
        if self.uri.starts_with("file://") {
            let path_str = &self.uri[7..];
            if let Some(parent) = Path::new(path_str).parent() {
                return parent.to_path_buf();
            }
        }
        std::env::current_dir().unwrap_or_default()
    }

    pub fn word_at(&self, pos: Position) -> Option<String> {
        let line = self.lines.get(pos.line as usize)?;
        let col = pos.character as usize;
        if col > line.len() {
            return None;
        }

        let chars: Vec<char> = line.chars().collect();
        if chars.is_empty() {
            return None;
        }

        let target_col = if col >= chars.len() {
            chars.len().saturating_sub(1)
        } else {
            col
        };

        if !is_identifier_char(chars[target_col]) && chars[target_col] != '@' {
            if target_col > 0 && is_identifier_char(chars[target_col - 1]) {
                // Look right behind caret
                let mut start = target_col - 1;
                while start > 0 && is_identifier_char(chars[start - 1]) {
                    start -= 1;
                }
                return Some(chars[start..target_col].iter().collect());
            }
            return None;
        }

        let mut start = target_col;
        while start > 0 && (is_identifier_char(chars[start - 1]) || chars[start - 1] == '@') {
            start -= 1;
        }

        let mut end = target_col;
        while end < chars.len() && is_identifier_char(chars[end]) {
            end += 1;
        }

        if start < end {
            Some(chars[start..end].iter().collect())
        } else {
            None
        }
    }

    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let import_path = self.get_import_path();
        let report =
            LanguageTools::check_with_import_path(&self.text, Some(&self.uri), import_path);

        let mut diagnostics = Vec::new();
        for diag in report.diagnostics {
            let (start_line, start_char, end_line, end_char) = match (diag.line, diag.column) {
                (Some(l), Some(c)) => {
                    let l_idx = l.saturating_sub(1) as u32;
                    let c_idx = c.saturating_sub(1) as u32;
                    let len = (diag.length as u32).max(1);
                    (l_idx, c_idx, l_idx, c_idx + len)
                }
                _ => (0, 0, 0, 1),
            };

            let severity = match diag.level {
                DiagnosticLevel::Error => Some(DiagnosticSeverity::ERROR),
                DiagnosticLevel::Warning => Some(DiagnosticSeverity::WARNING),
                DiagnosticLevel::Note | DiagnosticLevel::Info => {
                    Some(DiagnosticSeverity::INFORMATION)
                }
                DiagnosticLevel::Help => Some(DiagnosticSeverity::HINT),
            };

            let mut msg = diag.message;
            if let Some(ref label) = diag.label
                && !msg.contains(label)
            {
                msg = format!("{}: {}", msg, label);
            }
            if let Some(ref help) = diag.help {
                msg = format!("{}\nhelp: {}", msg, help);
            }
            for note in &diag.notes {
                msg = format!("{}\nnote: {}", msg, note);
            }

            diagnostics.push(Diagnostic {
                range: Range::new(start_line, start_char, end_line, end_char),
                severity,
                code: None,
                source: Some("parts".to_string()),
                message: msg,
            });
        }

        diagnostics
    }

    pub fn hover(&self, pos: Position) -> Option<Hover> {
        let word = self.word_at(pos)?;

        // 1. Keywords documentation
        let doc = match word.as_str() {
            "let" => Some(
                "### `let` declaration\nDeclares a mutable variable or function.\n\n```parts\nlet x = 42;\nlet add(a, b) = a + b;\n```",
            ),
            "fun" => Some(
                "### `fun` anonymous function\nDefines a lambda / closure expression.\n\n```parts\nlet square = fun(x) = x * x;\n```",
            ),
            "enum" => Some(
                "### `enum` definition\nDefines an algebraic data type with tagged variants.\n\n```parts\nenum Direction {\n    North(power),\n    South(power),\n    Stationary\n}\n```",
            ),
            "match" => Some(
                "### `match` expression\nPattern matches on enum variants, values, and wildcards.\n\n```parts\nmatch result {\n    Ok(v) => v,\n    Err(e) => 0,\n    _ => 0\n}\n```",
            ),
            "if" => Some(
                "### `if` conditional\nEvaluates a branch based on boolean truthiness.\n\n```parts\nif score >= 90 {\n    println(\"A\");\n} else {\n    println(\"B\");\n}\n```",
            ),
            "else" => Some("### `else` branch\nFallback branch for `if` statement."),
            "for" => Some(
                "### `for` loop\nActs as a while-loop or collection iterator.\n\n```parts\nfor i < 10 { i = i + 1; }\nfor item in collection { ... }\n```",
            ),
            "in" => Some("### `in` iterator clause\nIterates over strings, objects, or arrays."),
            "return" => {
                Some("### `return` statement\nReturns a value from the current function frame.")
            }
            "break" => Some("### `break` statement\nTerminates the nearest enclosing `for` loop."),
            "continue" => {
                Some("### `continue` statement\nSkips to the next iteration of the nearest loop.")
            }
            "part" => Some(
                "### `part` macro declaration\nDefines a hygienic syntactic macro.\n\n```parts\npart log {\n    (@msg) => { println(@msg); }\n}\n```",
            ),
            "import" => Some(
                "### `import` statement\nImports standard library modules or local files.\n\n```parts\nlet std = import `@std/std.pts`;\n```",
            ),
            "true" | "false" => Some("### Boolean literal"),
            "Int" => Some("### `Int` primitive type\n64-bit signed integer (`i64`)."),
            "Double" => {
                Some("### `Double` primitive type\n64-bit IEEE 754 floating point number (`f64`).")
            }
            "Bool" => Some("### `Bool` primitive type\nBoolean truth value (`true` or `false`)."),
            "String" => Some("### `String` primitive type\nReference-counted UTF-8 string."),
            "Bytes" => Some("### `Bytes` buffer type\nMutable byte buffer (`Vec<u8>`)."),
            "Result" => Some(
                "### `Result` enum\nRepresents success (`Result::Ok(val)`) or failure (`Result::Err(err)`).",
            ),
            "Option" => Some(
                "### `Option` enum\nRepresents an optional value (`Option::Some(val)`) or absence (`Option::None`).",
            ),
            "Ok" => Some("### `Result::Ok` variant\nWraps a successful value: `Result::Ok(val)`"),
            "Err" => Some("### `Result::Err` variant\nWraps an error value: `Result::Err(err)`"),
            "Some" => {
                Some("### `Option::Some` variant\nWraps an existing value: `Option::Some(val)`")
            }
            "None" => Some("### `Option::None` variant\nRepresents no value: `Option::None`"),
            "println" => Some(
                "### `println(...)`\nPrints arguments to standard output followed by a newline.",
            ),
            "print" => Some(
                "### `print(...)`\nPrints arguments to standard output without trailing newline.",
            ),
            "exec" => Some(
                "### `std.sys.exec(cmd)`\nExecutes a system shell command and returns `Result::Ok(stdout)` or `Result::Err(msg)`.",
            ),
            "env" => Some(
                "### `std.sys.env(key)`\nReads an environment variable and returns `Result`.",
            ),
            "len" => Some("### `.len()`\nReturns the length of a string, object, or byte buffer."),
            "upper" => Some("### `.upper()` / `std.str.upper(s)`\nConverts a string to uppercase."),
            "lower" => Some("### `.lower()` / `std.str.lower(s)`\nConverts a string to lowercase."),
            "strip_prefix" => Some(
                "### `.strip_prefix(prefix)`\nStrips `prefix` from a string, returning `Option::Some(rest)` or `Option::None`.",
            ),
            "strip_suffix" => Some(
                "### `.strip_suffix(suffix)`\nStrips `suffix` from a string, returning `Option::Some(rest)` or `Option::None`.",
            ),
            "byte_at" => Some(
                "### `.byte_at(index)`\nReturns `Result::Ok(codepoint)` at `index` in a string.",
            ),
            "join" => Some("### `.join(other)` / `std.str.join(a, b)`\nConcatenates two strings."),
            "unwrap" => Some(
                "### `.unwrap()`\nUnwraps `Result::Ok` or `Option::Some`, failing on `Err` / `None`.",
            ),
            "unwrap_or" => Some(
                "### `.unwrap_or(default)`\nUnwraps `Result` / `Option` or returns the fallback default value.",
            ),
            "unwrap_err" => Some(
                "### `.unwrap_err()`\nUnwraps the error payload of `Result::Err`.",
            ),
            "expect" => Some(
                "### `.expect(msg)`\nUnwraps `Result::Ok` / `Option::Some`, failing with `msg` on `Err` / `None`.",
            ),
            "ok_or" => Some(
                "### `.ok_or(err)`\nConverts `Option::Some(v)` to `Result::Ok(v)` and `Option::None` to `Result::Err(err)`.",
            ),
            "is_ok" => Some("### `.is_ok()`\nReturns `true` if the `Result` is `Ok`."),
            "is_err" => Some("### `.is_err()`\nReturns `true` if the `Result` is `Err`."),
            "is_some" => Some("### `.is_some()`\nReturns `true` if the `Option` is `Some`."),
            "is_none" => Some("### `.is_none()`\nReturns `true` if the `Option` is `None`."),
            "abs" => Some(
                "### `std.math.abs(x)`\nReturns the absolute value of an integer or double.",
            ),
            "pad" => Some(
                "### `std.bytes.pad(buf, alignment)`\nPads `buf` with zero bytes to a multiple of `alignment`.",
            ),
            "push" => Some("### `.push(byte)`\nAppends a single byte (`u8`) to a `Bytes` buffer."),
            "extend" => Some(
                "### `.extend(other)`\nAppends bytes from another `Bytes` buffer or `String`.",
            ),
            "slice" => Some(
                "### `.slice(start, end)`\nReturns `Result::Ok(Bytes)` for `[start..end]`.",
            ),
            "resize" => Some(
                "### `.resize(new_len, fill)`\nResizes a `Bytes` buffer to `new_len` using `fill` byte.",
            ),
            "fill" => Some("### `.fill(byte)`\nFills all bytes in a `Bytes` buffer with `byte`."),
            "to_string" => Some(
                "### `.to_string()`\nDecodes a `Bytes` buffer as UTF-8, returning `Result::Ok(String)`.",
            ),
            "to_hex" => Some("### `.to_hex()`\nFormats a `Bytes` buffer as lowercase hex."),
            "append_u8" => Some("### `.append_u8(val)`\nAppends a `u8` byte to a `Bytes` buffer."),
            "append_u16_be" => Some(
                "### `.append_u16_be(val)`\nAppends a big-endian 16-bit integer to a `Bytes` buffer.",
            ),
            "append_u16_le" => Some(
                "### `.append_u16_le(val)`\nAppends a little-endian 16-bit integer to a `Bytes` buffer.",
            ),
            "append_u32_be" => Some(
                "### `.append_u32_be(val)`\nAppends a big-endian 32-bit integer to a `Bytes` buffer.",
            ),
            "append_u32_le" => Some(
                "### `.append_u32_le(val)`\nAppends a little-endian 32-bit integer to a `Bytes` buffer.",
            ),
            "append_u64_be" => Some(
                "### `.append_u64_be(val)`\nAppends a big-endian 64-bit integer to a `Bytes` buffer.",
            ),
            "append_u64_le" => Some(
                "### `.append_u64_le(val)`\nAppends a little-endian 64-bit integer to a `Bytes` buffer.",
            ),
            _ => None,
        };

        if let Some(doc_text) = doc {
            return Some(Hover {
                contents: MarkupContent::markdown(doc_text),
                range: None,
            });
        }

        // 2. Check AST for user-defined symbols
        let mut parser = Parser::new(self.text.clone());
        if let Ok(ast) = parser.parse_all() {
            for node in &ast {
                match node {
                    Ast::Declare { name, value } => {
                        if name == &word {
                            let detail = match value.as_ref() {
                                Ast::Value(ParserValue::Fun { args, .. }) => {
                                    format!("let {}({})", name, args.join(", "))
                                }
                                _ => format!("let {}", name),
                            };
                            return Some(Hover {
                                contents: MarkupContent::markdown(format!(
                                    "```parts\n{}\n```\nUser-defined declaration.",
                                    detail
                                )),
                                range: None,
                            });
                        }
                    }
                    Ast::EnumDef { name, variants } => {
                        if name == &word {
                            let variant_strs: Vec<String> = variants
                                .iter()
                                .map(|v| {
                                    if v.fields.is_empty() {
                                        v.name.clone()
                                    } else {
                                        format!("{}({})", v.name, v.fields.join(", "))
                                    }
                                })
                                .collect();
                            return Some(Hover {
                                contents: MarkupContent::markdown(format!(
                                    "```parts\nenum {} {{\n    {}\n}}\n```",
                                    name,
                                    variant_strs.join(",\n    ")
                                )),
                                range: None,
                            });
                        }
                        for variant in variants {
                            if variant.name == word {
                                let sig = if variant.fields.is_empty() {
                                    format!("{}::{}", name, variant.name)
                                } else {
                                    format!(
                                        "{}::{}({})",
                                        name,
                                        variant.name,
                                        variant.fields.join(", ")
                                    )
                                };
                                return Some(Hover {
                                    contents: MarkupContent::markdown(format!(
                                        "```parts\n{}\n```\nVariant of enum `{}`.",
                                        sig, name
                                    )),
                                    range: None,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 3. Standard library registry modules and exports
        if let Some(std_doc) = std_hover_doc(&word) {
            return Some(Hover {
                contents: MarkupContent::markdown(std_doc),
                range: None,
            });
        }

        None
    }

    pub fn completion(&self, _pos: Position) -> Vec<CompletionItem> {
        let mut items = Vec::new();

        // 1. Keywords
        let keywords = [
            ("let", "let declaration", "let ${1:name} = ${2:value};"),
            ("fun", "anonymous function", "fun(${1:args}) = ${2:body}"),
            ("if", "if statement", "if ${1:condition} {\n    $0\n}"),
            (
                "if else",
                "if-else statement",
                "if ${1:condition} {\n    $2\n} else {\n    $0\n}",
            ),
            ("for", "for loop", "for ${1:condition} {\n    $0\n}"),
            (
                "for in",
                "for iterator",
                "for ${1:item} in ${2:collection} {\n    $0\n}",
            ),
            (
                "match",
                "match expression",
                "match ${1:target} {\n    ${2:pattern} => ${3:result},\n    _ => $0\n}",
            ),
            (
                "enum",
                "enum definition",
                "enum ${1:Name} {\n    ${2:Variant}\n}",
            ),
            ("return", "return statement", "return ${1:value};"),
            ("break", "break statement", "break;"),
            ("continue", "continue statement", "continue;"),
            (
                "import",
                "import statement",
                "let ${1:std} = import `@std/${2:std}.pts`;",
            ),
            (
                "part",
                "macro definition",
                "part ${1:name} {\n    (${2:@arg}) => {\n        $0\n    }\n}",
            ),
        ];

        for (kw, detail, snippet) in keywords {
            items.push(CompletionItem {
                label: kw.to_string(),
                kind: Some(CompletionItemKind::KEYWORD),
                detail: Some(detail.to_string()),
                documentation: None,
                insert_text: Some(snippet.to_string()),
                insert_text_format: Some(InsertTextFormat::SNIPPET),
            });
        }

        // 2. Builtin types and variants
        let builtins = [
            (
                "Result::Ok",
                CompletionItemKind::ENUM_MEMBER,
                "Result::Ok(${1:val})",
                "Ok variant",
            ),
            (
                "Result::Err",
                CompletionItemKind::ENUM_MEMBER,
                "Result::Err(${1:err})",
                "Err variant",
            ),
            (
                "Option::Some",
                CompletionItemKind::ENUM_MEMBER,
                "Option::Some(${1:val})",
                "Some variant",
            ),
            (
                "Option::None",
                CompletionItemKind::ENUM_MEMBER,
                "Option::None",
                "None variant",
            ),
            (
                "println",
                CompletionItemKind::FUNCTION,
                "println(${1:args});",
                "Print with newline",
            ),
            (
                "print",
                CompletionItemKind::FUNCTION,
                "print(${1:args});",
                "Print without newline",
            ),
            (
                "is_ok",
                CompletionItemKind::METHOD,
                "is_ok()",
                "Check Result::Ok",
            ),
            (
                "is_err",
                CompletionItemKind::METHOD,
                "is_err()",
                "Check Result::Err",
            ),
            (
                "is_some",
                CompletionItemKind::METHOD,
                "is_some()",
                "Check Option::Some",
            ),
            (
                "is_none",
                CompletionItemKind::METHOD,
                "is_none()",
                "Check Option::None",
            ),
            (
                "unwrap",
                CompletionItemKind::METHOD,
                "unwrap()",
                "Unwrap value or fail",
            ),
            (
                "unwrap_or",
                CompletionItemKind::METHOD,
                "unwrap_or(${1:default})",
                "Unwrap with fallback",
            ),
            (
                "unwrap_err",
                CompletionItemKind::METHOD,
                "unwrap_err()",
                "Unwrap error message",
            ),
            (
                "expect",
                CompletionItemKind::METHOD,
                "expect(${1:\"msg\"})",
                "Unwrap with message",
            ),
            (
                "ok_or",
                CompletionItemKind::METHOD,
                "ok_or(${1:err})",
                "Convert Option to Result",
            ),
            (
                "len",
                CompletionItemKind::METHOD,
                "len()",
                "Length of collection",
            ),
            (
                "join",
                CompletionItemKind::METHOD,
                "join(${1:other})",
                "Concatenate string",
            ),
            (
                "strip_prefix",
                CompletionItemKind::METHOD,
                "strip_prefix(${1:prefix})",
                "Strip string prefix (Option)",
            ),
            (
                "strip_suffix",
                CompletionItemKind::METHOD,
                "strip_suffix(${1:suffix})",
                "Strip string suffix (Option)",
            ),
            (
                "byte_at",
                CompletionItemKind::METHOD,
                "byte_at(${1:index})",
                "Character codepoint at index (Result)",
            ),
            (
                "upper",
                CompletionItemKind::METHOD,
                "upper()",
                "Uppercase string",
            ),
            (
                "lower",
                CompletionItemKind::METHOD,
                "lower()",
                "Lowercase string",
            ),
            (
                "to_hex",
                CompletionItemKind::METHOD,
                "to_hex()",
                "Hex representation of bytes",
            ),
            (
                "to_string",
                CompletionItemKind::METHOD,
                "to_string()",
                "Decode bytes as UTF-8 (Result)",
            ),
            (
                "slice",
                CompletionItemKind::METHOD,
                "slice(${1:start}, ${2:end})",
                "Slice byte buffer (Result)",
            ),
            (
                "extend",
                CompletionItemKind::METHOD,
                "extend(${1:other})",
                "Extend byte buffer",
            ),
            (
                "resize",
                CompletionItemKind::METHOD,
                "resize(${1:new_len}, ${2:fill})",
                "Resize byte buffer",
            ),
            (
                "fill",
                CompletionItemKind::METHOD,
                "fill(${1:byte})",
                "Fill byte buffer",
            ),
            (
                "push",
                CompletionItemKind::METHOD,
                "push(${1:byte})",
                "Append byte to buffer",
            ),
            (
                "abs",
                CompletionItemKind::FUNCTION,
                "abs(${1:x})",
                "std.math.abs — absolute value",
            ),
            (
                "pad",
                CompletionItemKind::FUNCTION,
                "pad(${1:buf}, ${2:alignment})",
                "std.bytes.pad — zero-pad buffer to alignment",
            ),
            (
                "append_u8",
                CompletionItemKind::METHOD,
                "append_u8(${1:val})",
                "Append u8 byte to buffer",
            ),
            (
                "append_u16_be",
                CompletionItemKind::METHOD,
                "append_u16_be(${1:val})",
                "Append 16-bit big-endian integer",
            ),
            (
                "append_u16_le",
                CompletionItemKind::METHOD,
                "append_u16_le(${1:val})",
                "Append 16-bit little-endian integer",
            ),
            (
                "append_u32_be",
                CompletionItemKind::METHOD,
                "append_u32_be(${1:val})",
                "Append 32-bit big-endian integer",
            ),
            (
                "append_u32_le",
                CompletionItemKind::METHOD,
                "append_u32_le(${1:val})",
                "Append 32-bit little-endian integer",
            ),
            (
                "append_u64_be",
                CompletionItemKind::METHOD,
                "append_u64_be(${1:val})",
                "Append 64-bit big-endian integer",
            ),
            (
                "append_u64_le",
                CompletionItemKind::METHOD,
                "append_u64_le(${1:val})",
                "Append 64-bit little-endian integer",
            ),
        ];

        let mut seen_labels = std::collections::HashSet::new();

        for (label, kind, snippet, detail) in builtins {
            seen_labels.insert(label.to_string());
            items.push(CompletionItem {
                label: label.to_string(),
                kind: Some(kind),
                detail: Some(detail.to_string()),
                documentation: None,
                insert_text: Some(snippet.to_string()),
                insert_text_format: Some(InsertTextFormat::SNIPPET),
            });
        }

        // 3. Standard Library Module imports and exports from Rust registry
        let registry = crate::std::std_registry();
        let mut mod_keys: Vec<&'static str> = registry.modules.keys().copied().collect();
        mod_keys.sort_unstable();

        for mod_key in &mod_keys {
            let import_label = if *mod_key == "std" {
                "@std/std.pts".to_string()
            } else {
                format!("@std/{}.pts", mod_key.trim_start_matches("std."))
            };
            let doc = std_module_summary(mod_key, &registry.modules[mod_key]);
            if seen_labels.insert(import_label.clone()) {
                items.push(CompletionItem {
                    label: import_label.clone(),
                    kind: Some(CompletionItemKind::MODULE),
                    detail: Some("Standard Library Module".to_string()),
                    documentation: Some(MarkupContent::markdown(doc)),
                    insert_text: Some(import_label),
                    insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
                });
            }
        }

        for mod_key in &mod_keys {
            let spec = &registry.modules[mod_key];
            let mut const_names: Vec<&'static str> = spec.constants.keys().copied().collect();
            const_names.sort_unstable();
            for const_name in const_names {
                if seen_labels.insert(const_name.to_string()) {
                    items.push(CompletionItem {
                        label: const_name.to_string(),
                        kind: Some(CompletionItemKind::CONSTANT),
                        detail: Some(format!("{}.{}", mod_key, const_name)),
                        documentation: None,
                        insert_text: Some(const_name.to_string()),
                        insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
                    });
                }
            }

            let mut fn_names: Vec<&'static str> = spec.natives.keys().copied().collect();
            fn_names.sort_unstable();
            for fn_name in fn_names {
                if seen_labels.insert(fn_name.to_string()) {
                    let native = &spec.natives[fn_name];
                    let snippet = if native.arity == 0 {
                        format!("{}()", fn_name)
                    } else {
                        let args: Vec<String> = (1..=native.arity)
                            .map(|i| format!("${{{}:arg{}}}", i, i))
                            .collect();
                        format!("{}({})", fn_name, args.join(", "))
                    };
                    items.push(CompletionItem {
                        label: fn_name.to_string(),
                        kind: Some(CompletionItemKind::FUNCTION),
                        detail: Some(format!("{}.{}", mod_key, fn_name)),
                        documentation: None,
                        insert_text: Some(snippet),
                        insert_text_format: Some(InsertTextFormat::SNIPPET),
                    });
                }
            }
        }

        // 4. Local document symbols
        let mut scanner = Scanner::new(ScannerRule::get_default_rules(), self.text.clone());
        while let Ok(tok) = scanner.get_next() {
            if tok.kind == TokenType::Special && tok.lexeme == "EOF" {
                break;
            }
            if tok.kind == TokenType::Identifier && seen_labels.insert(tok.lexeme.clone()) {
                items.push(CompletionItem {
                    label: tok.lexeme.clone(),
                    kind: Some(CompletionItemKind::VARIABLE),
                    detail: Some("Document symbol".to_string()),
                    documentation: None,
                    insert_text: Some(tok.lexeme),
                    insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
                });
            }
        }
        items
    }

    pub fn document_symbols(&self) -> Vec<DocumentSymbol> {
        let mut symbols = Vec::new();
        let mut parser = Parser::new(self.text.clone());

        if let Ok(ast) = parser.parse_all() {
            for (idx, node) in ast.into_iter().enumerate() {
                let default_range = Range::new(idx as u32, 0, idx as u32, 1);
                match node {
                    Ast::Declare { name, value } => {
                        let kind = match value.as_ref() {
                            Ast::Value(ParserValue::Fun { .. }) => SymbolKind::FUNCTION,
                            _ => SymbolKind::VARIABLE,
                        };
                        symbols.push(DocumentSymbol {
                            name,
                            detail: None,
                            kind,
                            range: default_range,
                            selection_range: default_range,
                            children: None,
                        });
                    }
                    Ast::EnumDef { name, variants } => {
                        let variant_symbols: Vec<DocumentSymbol> = variants
                            .into_iter()
                            .map(|v| DocumentSymbol {
                                name: v.name,
                                detail: None,
                                kind: SymbolKind::ENUM_MEMBER,
                                range: default_range,
                                selection_range: default_range,
                                children: None,
                            })
                            .collect();

                        symbols.push(DocumentSymbol {
                            name,
                            detail: None,
                            kind: SymbolKind::ENUM,
                            range: default_range,
                            selection_range: default_range,
                            children: Some(variant_symbols),
                        });
                    }
                    _ => {}
                }
            }
        }

        symbols
    }

    pub fn definition(&self, pos: Position) -> Option<Location> {
        let word = self.word_at(pos)?;

        // Search lines for declaration
        for (line_idx, line) in self.lines.iter().enumerate() {
            if let Some(col_idx) = line.find(&format!("let {}", word)) {
                let start_char = col_idx as u32 + 4;
                let end_char = start_char + word.len() as u32;
                return Some(Location {
                    uri: self.uri.clone(),
                    range: Range::new(line_idx as u32, start_char, line_idx as u32, end_char),
                });
            }
            if let Some(col_idx) = line.find(&format!("enum {}", word)) {
                let start_char = col_idx as u32 + 5;
                let end_char = start_char + word.len() as u32;
                return Some(Location {
                    uri: self.uri.clone(),
                    range: Range::new(line_idx as u32, start_char, line_idx as u32, end_char),
                });
            }
            if let Some(col_idx) = line.find(&format!("part {}", word)) {
                let start_char = col_idx as u32 + 5;
                let end_char = start_char + word.len() as u32;
                return Some(Location {
                    uri: self.uri.clone(),
                    range: Range::new(line_idx as u32, start_char, line_idx as u32, end_char),
                });
            }
        }

        None
    }

    pub fn format(&self) -> Vec<TextEdit> {
        // Return cleaned up full document edit if formatted
        let total_lines = self.lines.len() as u32;
        let last_line_len = self.lines.last().map(|l| l.len() as u32).unwrap_or(0);
        let whole_range = Range::new(0, 0, total_lines, last_line_len);

        // Normalize trailing whitespace and ensure newline at EOF
        let mut formatted = String::new();
        for line in &self.lines {
            formatted.push_str(line.trim_end());
            formatted.push('\n');
        }

        vec![TextEdit {
            range: whole_range,
            new_text: formatted,
        }]
    }
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn std_module_summary(mod_key: &str, spec: &crate::std::StdModuleSpec) -> String {
    let mut parts = Vec::new();
    if !spec.submodules.is_empty() {
        let mut subs: Vec<&str> = spec.submodules.keys().copied().collect();
        subs.sort_unstable();
        parts.push(format!("Submodules: `{}`", subs.join("`, `")));
    }
    if !spec.constants.is_empty() {
        let mut consts: Vec<&str> = spec.constants.keys().copied().collect();
        consts.sort_unstable();
        parts.push(format!("Constants: `{}`", consts.join("`, `")));
    }
    if !spec.natives.is_empty() {
        let mut fns: Vec<&str> = spec.natives.keys().copied().collect();
        fns.sort_unstable();
        parts.push(format!("Functions: `{}`", fns.join("`, `")));
    }
    if parts.is_empty() {
        format!("Standard library module `{}`.", mod_key)
    } else {
        format!(
            "### `{}`\nStandard library module.\n\n{}",
            mod_key,
            parts.join("\n\n")
        )
    }
}

fn std_hover_doc(word: &str) -> Option<String> {
    let registry = crate::std::std_registry();

    let mod_key = if word == "std" {
        Some("std")
    } else {
        registry
            .modules
            .keys()
            .find(|k| k.strip_prefix("std.") == Some(word))
            .copied()
    };
    if let Some(key) = mod_key {
        return Some(std_module_summary(key, &registry.modules[key]));
    }

    let mut mod_keys: Vec<&'static str> = registry.modules.keys().copied().collect();
    mod_keys.sort_unstable();

    let mut export_paths = Vec::new();
    let mut const_val_str = None;
    let mut native_arity = None;

    for m in &mod_keys {
        let spec = &registry.modules[m];
        if let Some(c) = spec.constants.get(word) {
            export_paths.push(format!("{}.{}", m, word));
            const_val_str = Some(format!("{:?}", c));
        }
        if let Some(f) = spec.natives.get(word) {
            export_paths.push(format!("{}.{}", m, word));
            native_arity = Some(f.arity);
        }
    }

    if !export_paths.is_empty() {
        let header = format!("### `{}`", export_paths.join("`, `"));
        return if let Some(cval) = const_val_str {
            Some(format!("{}\nStandard library constant (`{}`).", header, cval))
        } else if let Some(arity) = native_arity {
            Some(format!(
                "{}\nStandard library function (arity: {}).",
                header, arity
            ))
        } else {
            Some(header)
        };
    }

    if let Some(f) = crate::std::core_global_by_name(word) {
        return Some(format!(
            "### `{}`\nBuilt-in native function (arity: {}).",
            f.name, f.arity
        ));
    }

    None
}
