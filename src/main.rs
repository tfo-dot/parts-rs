use clap::Parser;
use parts_rs::{compiler::Compiler, disassemble, parser::Parser as Partser, vm::VM};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Sets input
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    #[arg(short, long, value_name = "DBG")]
    debug: bool,
}

fn main() {
    let cli = Cli::parse();

    let content = fs::read_to_string(cli.input).unwrap();

    if cli.debug {
        println!("Code: \n{}\n", content)
    }

    let mut p = Partser::new(content);

    let ast = p.parse_all().expect("Got error parser lol");

    if cli.debug {
        println!("Ast output:");

        for stmt in &ast {
            println!("{:?}", stmt);
        }

        println!();
    }

    let mut c = Compiler::new();

    let bc = c.compile_all(ast).expect("Got error cmp lol");

    if cli.debug {
        println!("Bytecode: {:?}\n", bc);

        println!("Consts:");

        for constant in &c.constant_pool {
            println!("{:?}", constant);
        }

        println!();

        disassemble::disassemble(&bc, &c.constant_pool);

        println!();
    }

    let mut vm = VM::new(bc, c.constant_pool);

    let res = vm.run().expect("Got error vm lol");

    if res.is_some() {
        if cli.debug {
            println!("Output: \n {:?}", res.unwrap())
        } else {
            println!("{}", res.unwrap())
        }
    }
}
