use clap::Parser;
use parts_rs::{compiler::Compiler, disassemble, parser::Parser as Partser, vm::VM};
use std::{fs, path::PathBuf, time::Instant};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "DEBUG")]
    debug: bool,
    #[arg(short, long, value_name = "SHEBANG")]
    shebang: bool,
    #[arg(short, long, value_name = "TIMED")]
    timed: bool,
    input: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    let content = if cli.shebang {
        let content = fs::read_to_string(cli.input).unwrap();

        let split = content.split_once("\n").unwrap();

        split.1.to_string()
    } else {
        fs::read_to_string(cli.input).unwrap()
    };

    if cli.debug {
        println!("Code: \n{}\n", content)
    }

    let start_time_c = Instant::now();

    let mut p = Partser::new(content);

    let ast = p.parse_all().expect("Got error parser lol");

    if cli.timed {
        println!("Compilation took: {:?} ", start_time_c.elapsed());
    }

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

    let start_time_e = Instant::now();

    let mut vm = VM::new(bc, c.constant_pool);

    let res = vm.run().expect("Got error vm lol");

    if cli.timed {
        println!("Execution took: {:?} ", start_time_e.elapsed());
    }

    if res.is_some() {
        if cli.debug {
            println!("Output: \n {:?}", res.unwrap())
        } else {
            println!("{}", res.unwrap())
        }
    }
}
