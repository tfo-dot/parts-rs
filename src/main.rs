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
        return get_bytecode(config);
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

#[repr(C)]
struct BytecodeHeader {
    magic: [u8; 4],
    version: u32,
    source_hash: u64,
    payload_size: u64,
    consts_offset: u64,
}

fn get_bytecode(config: Cli) -> CompilerOutput {
    let source_path = config.input.clone();
    let cache_path = config.input.with_extension("ptc");
    let source_content = fs::read(source_path).expect("Failed to read source");
    let current_hash = xxh3_64(&source_content);

    if let Ok(mut file) = File::open(&cache_path) {
        let mut header_buf = [0u8; std::mem::size_of::<BytecodeHeader>()];

        if file.read_exact(&mut header_buf).is_ok() {
            let magic = &header_buf[0..4];
            let version = u32::from_le_bytes(header_buf[4..8].try_into().unwrap());
            let source_hash = u64::from_le_bytes(header_buf[8..16].try_into().unwrap());
            let payload_size = u64::from_le_bytes(header_buf[16..24].try_into().unwrap());
            let consts_offset = u64::from_le_bytes(header_buf[24..32].try_into().unwrap());

            let header = BytecodeHeader {
                magic: magic.try_into().unwrap(),
                version,
                source_hash,
                payload_size,
                consts_offset,
            };

            if header.magic == [0x7F, b'P', b'T', b'S']
                && header.version == 1
                && header.source_hash == current_hash
            {
                let mut buff = Vec::with_capacity(
                    header.payload_size as usize + header.consts_offset as usize,
                );

                file.read_to_end(&mut buff).unwrap();

                let encoded_c = buff[0..header.consts_offset as usize].to_vec();

                let bytecode = buff[header.consts_offset as usize
                    ..header.consts_offset as usize + header.payload_size as usize]
                    .to_vec();

                return CompilerOutput {
                    code: bytecode,
                    consts: Value::decode(encoded_c, false, 0).0,
                };
            }
        }
    }

    let content = if config.shebang {
        let str_content = String::from_utf8(source_content).expect("Can't read utf8 contents");

        let split = str_content.split_once("\n").unwrap();

        split.1.to_string()
    } else {
        String::from_utf8(source_content).unwrap()
    };

    let mut p = Partser::new(content);

    let ast = p.parse_all().expect("Got error parser lol");

    let mut c = Compiler::new();

    let bc = c.compile_all(ast).expect("Got error cmp lol");

    save_cache(&cache_path, &bc, c.constant_pool.clone(), current_hash);
    return CompilerOutput {
        code: bc,
        consts: c.constant_pool,
    };
}

struct CompilerOutput {
    code: Vec<u8>,
    consts: Vec<Value>,
}

fn save_cache(path: &Path, raw_bc: &[u8], constant_pool: Vec<Value>, hash: u64) {
    let encoded_c: Vec<_> = constant_pool.iter().map(|c| c.encode()).flatten().collect();

    let data = raw_bc;

    let temp_path = path.with_extension("tmp");
    let mut file = File::create(&temp_path).unwrap();

    let mut header_bytes = Vec::new();
    header_bytes.extend_from_slice(&[0x7F, b'P', b'T', b'S']);
    header_bytes.extend_from_slice(&1u32.to_le_bytes());
    header_bytes.extend_from_slice(&hash.to_le_bytes());
    header_bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
    header_bytes.extend_from_slice(&(encoded_c.len() as u64).to_le_bytes());

    file.write_all(&header_bytes).unwrap();
    file.write_all(&encoded_c).unwrap();
    file.write_all(data).unwrap();
    fs::rename(temp_path, path).unwrap();
}
