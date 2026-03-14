use clap::Parser;
use parts_rs::{
    compiler::{Compiler, Value},
    disassemble,
    parser::Parser as Partser,
    vm::VM,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use xxhash_rust::xxh3::xxh3_64;

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "DEBUG")]
    debug: bool,
    #[arg(short, long, value_name = "SHEBANG")]
    shebang: bool,
    #[arg(short, long, value_name = "TIMED")]
    timed: bool,
    #[arg(short, long, value_name = "CACHED")]
    cached: bool,
    input: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    let res = get_code(cli.clone());

    let start_time_e = Instant::now();

    let mut vm = VM::new(res.code, res.consts);

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

fn get_code(config: Cli) -> CompilerOutput {
    if config.cached {
        if config.debug {
            println!("Attempting to use the cached version");
        }
        return get_bytecode(&config.input, &config.input.with_extension("ptc"));
    }

    let content = if config.shebang {
        let content = fs::read_to_string(config.input).unwrap();

        let split = content.split_once("\n").unwrap();

        split.1.to_string()
    } else {
        fs::read_to_string(config.input).unwrap()
    };

    if config.debug {
        println!("Code: \n{}\n", content);
    }

    let mut p = Partser::new(content);

    let start_time_c = Instant::now();

    let ast = p.parse_all().expect("Got error parser lol");

    if config.timed {
        println!("Compilation took: {:?} ", start_time_c.elapsed());
    }

    if config.debug {
        println!("Ast output:");

        for stmt in &ast {
            println!("{:?}", stmt);
        }

        println!();
    }

    let mut c = Compiler::new();

    let bc = c.compile_all(ast).expect("Got error cmp lol");

    if config.debug {
        println!("Bytecode: {:?}\n", bc);

        println!("Consts:");

        for constant in &c.constant_pool {
            println!("{:?}", constant);
        }

        println!();

        disassemble::disassemble(&bc, &c.constant_pool);

        println!();
    }

    return CompilerOutput {
        code: bc,
        consts: c.constant_pool,
    };
}

struct BytecodeHeader {
    magic: [u8; 4],
    version: u32,
    source_hash: u64,
    payload_size: u64,
}

fn get_bytecode(source_path: &Path, cache_path: &Path) -> CompilerOutput {
    let source_content = fs::read(source_path).expect("Failed to read source");
    let current_hash = xxh3_64(&source_content);

    if let Ok(mut file) = File::open(cache_path) {
        let mut header_buf = [0u8; std::mem::size_of::<BytecodeHeader>()];

        if file.read_exact(&mut header_buf).is_ok() {
            let header: &BytecodeHeader =
                unsafe { &*(header_buf.as_ptr() as *const BytecodeHeader) };

            if header.magic == [0x7F, b'P', b'T', b'S']
                && header.version == 1
                && header.source_hash == current_hash
            {
                let mut bytecode = Vec::with_capacity(header.payload_size as usize);
                file.read_to_end(&mut bytecode).unwrap();

                return CompilerOutput {
                    code: bytecode,
                    consts: vec![],
                };
            }
        }
    }

    let str_content = String::from_utf8(source_content).expect("LOL");

    let mut p = Partser::new(str_content);

    let ast = p.parse_all().expect("Got error parser lol");

    let mut c = Compiler::new();

    let bc = c.compile_all(ast).expect("Got error cmp lol");

    save_cache(cache_path, &bc, current_hash);
    return CompilerOutput {
        code: bc,
        consts: c.constant_pool,
    };
}

struct CompilerOutput {
    code: Vec<u8>,
    consts: Vec<Value>,
}

fn save_cache(path: &Path, data: &[u8], hash: u64) {
    let header = BytecodeHeader {
        magic: [0x7F, b'P', b'T', b'S'],
        version: 1,
        source_hash: hash,
        payload_size: data.len() as u64,
    };

    // Standard Rust safety: Write to tmp then rename
    let temp_path = path.with_extension("tmp");
    let mut file = File::create(&temp_path).unwrap();

    let header_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            (&header as *const BytecodeHeader) as *const u8,
            std::mem::size_of::<BytecodeHeader>(),
        )
    };

    file.write_all(header_bytes).unwrap();
    file.write_all(data).unwrap();
    fs::rename(temp_path, path).unwrap();
}
