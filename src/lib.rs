pub mod compiler;
pub mod disassemble;
pub mod emitter;
pub mod engine;
pub mod optimize;
pub mod parser;
pub mod parser_rules;
pub mod parser_rules_postfix;
pub mod scanner;
pub mod scanner_rules;
pub mod std;
pub mod value;
pub mod vm;

mod utils;

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "lib/"]
pub struct Assets;
