use clap::Parser;
use parts::{
    compiler::Compiler,
    disassemble,
    emitter::Emitter,
    optimize::{AstOptimizer, IrOptimizer},
    parser::Parser as Partser,
    value::Value,
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
    #[arg(short, long, value_name = "OPTIMIZE")]
    optimize: bool,
    input: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    let res = get_code(cli.clone());

    let start_time_e = Instant::now();

    let mut vm = VM::new(res.code, res.consts);

    let res = vm
        .run()
        .inspect_err(|e| println!("{:?} at {:04}", e, vm.frames.last().expect("msg").ip))
        .expect("msg");

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
        let start_time_c = Instant::now();

        if config.debug {
            println!("Attempting to use the cached version");
        }

        let btc = get_bytecode(config.clone());

        if config.timed {
            println!("Decoding took: {:?} ", start_time_c.elapsed());
        }

        if config.debug {
            println!("Bytecode: {:?}\n", btc.code);

            println!("Consts:");

            for constant in &btc.consts {
                println!("{:?}", constant);
            }

            println!();

            disassemble::disassemble(&btc.code, &btc.consts);

            println!();
        }

        return btc;
    }

    let raw_path = config.input.clone();

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

    let start_time_p = Instant::now();

    let mut ast = p.parse_all().expect("Got error parser lol");

    if config.timed {
        println!("Parsing took: {:?} ", start_time_p.elapsed());
    }

    if config.optimize {
        let start_time_o = Instant::now();

        let mut optimizer = AstOptimizer::new();

        optimizer.collect_all(&ast);

        let mut pass = 0;

        {
            let mut changed = true;
            while changed {
                pass += 1;
                let old_ast = ast.clone();
                optimizer.optimize_all(&mut ast);
                changed = old_ast != ast;
            }
        }

        if config.timed {
            println!(
                "Optimization took: {:?} (passes: {})",
                start_time_o.elapsed(),
                pass
            );
        }
    }

    if config.debug {
        println!("Ast output:");

        for stmt in &ast {
            println!("{:?}", stmt);
        }

        println!();
    }

    let mut c = Compiler::new(raw_path.parent().unwrap().to_path_buf());

    let start_time_p = Instant::now();

    let mut ir = c.compile_all(ast).expect("Got error cmp lol");

    if config.debug && config.optimize {
        println!("Compilation took: {:?} ", start_time_p.elapsed());
    }

    if config.debug {
        println!("Before optimization {}", ir.len());
    }
    if config.optimize {
        ir = IrOptimizer::optimize(ir);
    }

    if config.debug && config.optimize {
        println!("After optimization {}", ir.len());
    }

    if config.debug {
        println!("IR output:");

        for node in &ir {
            println!("{:?}", node);
        }

        println!();
    }

    let bc = Emitter {}.emit(ir);

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
    let source_content = fs::read(&source_path).expect("Failed to read source");
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

                let encoded_c = &buff[0..header.consts_offset as usize];

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

    let mut ast = p.parse_all().expect("Got error parser lol");

    if config.optimize {
        let mut optimizer = AstOptimizer::new();
        optimizer.collect_all(&ast);
        let mut changed = true;
        while changed {
            let old_ast = ast.clone();
            optimizer.optimize_all(&mut ast);
            changed = old_ast != ast;
        }
    }

    let mut c = Compiler::new(source_path.parent().unwrap().to_path_buf());
    let mut ir = c.compile_all(ast).expect("Got error cmp lol");

    if config.optimize {
        ir = IrOptimizer::optimize(ir);
    }

    let bc = Emitter {}.emit(ir);
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
    let mut encoded_c = Vec::new();
    for c in &constant_pool {
        c.encode(&mut encoded_c);
    }

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
