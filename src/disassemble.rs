use crate::compiler::{OpCode, Value};

pub fn disassemble(code: &[u8], constants: &[Value]) {
    println!("--- Disassembly ---");
    let mut offset = 0;
    while offset < code.len() {
        offset = disassemble_instruction(code, offset, constants);
    }
}

fn disassemble_instruction(code: &[u8], offset: usize, constants: &[Value]) -> usize {
    print!("{:04} ", offset);
    let byte = code[offset];

    let opcode = match OpCode::try_from(byte) {
        Ok(op) => op,
        Err(_) => {
            println!("Unknown OpCode: {:#04X}", byte);
            return offset + 1;
        }
    };

    match opcode {
        OpCode::Load => {
            let reg = code[offset + 1];
            let type_byte = code[offset + 2];
            let val_type = OpCode::try_from(type_byte).unwrap();
            print!("{:-12} Reg: {:<3} Type: {:?}", "LOAD", reg, val_type);

            match val_type {
                OpCode::ConstInt | OpCode::ConstDouble => {
                    println!(" (8 bytes raw data)");
                    offset + 11
                }
                OpCode::ConstBool => {
                    println!(" Value: {}", code[offset + 3] != 0);
                    offset + 4
                }
                OpCode::ConstString | OpCode::ConstRef | OpCode::ConstFun | OpCode::ConstObj => {
                    let idx = code[offset + 3] as usize;
                    println!(
                        " ConstIdx: {} ({:?})",
                        idx,
                        constants
                            .get(idx)
                            .map(|v| v.to_string())
                            .unwrap_or_default()
                    );
                    offset + 4
                }
                OpCode::ConstReg => {
                    println!(" FromReg: {}", code[offset + 3]);
                    offset + 4
                }

                _ => {
                    println!();
                    offset + 3
                }
            }
        }
        OpCode::Call => {
            let ret = code[offset + 1];
            let func = code[offset + 2];
            let args_count = code[offset + 3];
            println!(
                "{:-12} RetReg: {:<3} FuncReg: {:<3} Args: {}",
                "CALL", ret, func, args_count
            );
            offset + 4 + args_count as usize
        }
        OpCode::LoadNative => {
            let reg = code[offset + 1];
            let idx = code[offset + 2] as usize;
            println!(
                "{:-12} Reg: {:<3} NativeIdx: {} ({})",
                "LOAD_NATIVE",
                reg,
                idx,
                constants
                    .get(idx)
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            );
            offset + 3
        }
        OpCode::Binary => {
            let op = code[offset + 1];
            let dest = code[offset + 2];
            let left = code[offset + 3];
            let right = code[offset + 4];
            println!(
                "{:-12} Op: {} Dest: {} L: {} R: {}",
                "BINARY", op, dest, left, right
            );
            offset + 5
        }
        OpCode::Return => {
            println!("{:-12} Reg: {}", "RETURN", code[offset + 1]);
            offset + 2
        }
        OpCode::Jump | OpCode::JumpBy => {
            let jump_offset = u16::from_le_bytes([code[offset + 1], code[offset + 2]]) as usize;
            let mut target = jump_offset;
            let name = if opcode == OpCode::Jump {
                target += offset + 3;
                "JUMP"
            } else {
                "JUMP_BY"
            };
            println!("{:-12} {:04} (offset: {})", name, target, jump_offset);
            offset + 3
        }

        OpCode::JumpIf | OpCode::JumpNot => {
            let reg = code[offset + 1];
            let jump_offset = u16::from_le_bytes([code[offset + 2], code[offset + 3]]) as usize;
            let target = offset + 4 + jump_offset;
            let name = if opcode == OpCode::JumpIf {
                "JUMP_IF"
            } else {
                "JUMP_NOT"
            };
            println!("{:-12} Reg: {:<3} Target: {:04}", name, reg, target);
            offset + 4
        }

        OpCode::JumpBack => {
            let jump_offset = u16::from_le_bytes([code[offset + 1], code[offset + 2]]) as usize;
            // JumpBack moves the IP backwards from the start of the next instruction
            let target = (offset + 3).saturating_sub(jump_offset);
            println!(
                "{:-12} {:04} (backwards: {})",
                "JUMP_BACK", target, jump_offset
            );
            offset + 3
        }
        _ => {
            println!("{:?}", opcode);
            offset + 1
        }
    }
}
