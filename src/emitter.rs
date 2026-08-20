use rustc_hash::FxHashMap;

use crate::compiler::IrOp;
use crate::define_opcodes;

pub struct Emitter {}

define_opcodes! {
    // Constants
    ConstInt    = 0x00,
    ConstDouble = 0x01,
    ConstBool   = 0x02,
    ConstString = 0x03,
    ConstRef    = 0x04,
    ConstFun    = 0x05,
    ConstObj    = 0x06,
    ConstReg    = 0x07,
    ConstEnum   = 0x08,

    // Flow Control
    Return      = 0x10,
    Call        = 0x11,
    Binary      = 0x12,
    Jump        = 0x13,
    JumpNot     = 0x16,
    Inc         = 0x18,
    Dec         = 0x19,

    //Register movements
    Load        = 0x20,
    GetProperty = 0x21,
    SetProperty = 0x22,
    GetPropertyDyn = 0x23,
    SetPropertyDyn = 0x24,
    LoadNative  = 0x25,
    LoadGlobal  = 0x26
}

impl Emitter {
    fn get_byte_length(op: IrOp) -> i64 {
        match op {
            IrOp::LoadConst { dest: _, idx: _ } => 4,
            IrOp::LoadInt { dest: _, val: _ } => 11,
            IrOp::LoadDouble { dest: _, val: _ } => 11,
            IrOp::LoadBool { dest: _, val: _ } => 4,
            IrOp::LoadReg { dest: _, src: _ } => 4,
            IrOp::LoadNative { dest: _, src: _ } => 3,
            IrOp::LoadGlobal { dest: _, src: _ } => 3,
            IrOp::LoadFun { dest: _, src: _ } => 4,
            IrOp::LoadObject { dest: _, src: _ } => 4,
            IrOp::GetProperty {
                dest: _,
                obj: _,
                key: _,
            } => 4,
            IrOp::GetPropertyDyn {
                dest: _,
                obj: _,
                key: _,
            } => 4,
            IrOp::SetProperty {
                obj: _,
                key: _,
                val: _,
            } => 4,
            IrOp::SetPropertyDyn {
                obj: _,
                key: _,
                val: _,
            } => 4,
            IrOp::Return { value: _ } => 2,
            IrOp::Call {
                dest: _,
                what: _,
                args,
            } => (4 + args.len()).try_into().unwrap(),
            IrOp::Binary {
                dest: _,
                op: _,
                left: _,
                right: _,
            } => 5,
            IrOp::JumpNot {
                target: _,
                condition: _,
            } => 4,
            IrOp::Jump { target: _ } => 3,
            IrOp::Label(_) => 0,
            IrOp::Inc { target: _ } => 2,
            IrOp::Dec { target: _ } => 2,
            IrOp::LoadEnumField {
                dest: _,
                enum_idx: _,
                tag: _,
                args: _,
            } => 5,
        }
    }

    pub fn emit(&mut self, ir: Vec<IrOp>) -> Vec<u8> {
        let mut current_byte_offset = 0;
        let mut label_offsets = FxHashMap::default();

        for op in &ir {
            match op {
                IrOp::Label(id) => {
                    label_offsets.insert(*id, current_byte_offset);
                }
                _ => current_byte_offset += Self::get_byte_length(op.clone()),
            }
        }

        let mut buff = Vec::new();

        for op in ir {
            match op {
                IrOp::LoadConst { dest, idx } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstRef as u8);
                    buff.push(idx);
                }
                IrOp::LoadInt { dest, val } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstInt as u8);
                    buff.extend(val.to_le_bytes());
                }
                IrOp::LoadDouble { dest, val } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstDouble as u8);
                    buff.extend(val.to_le_bytes());
                }

                IrOp::LoadBool { dest, val } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstBool as u8);
                    buff.push(val as u8);
                }
                IrOp::LoadReg { dest, src } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstReg as u8);
                    buff.push(src);
                }
                IrOp::LoadNative { dest, src } => {
                    buff.push(OpCode::LoadNative as u8);
                    buff.push(dest);
                    buff.push(src);
                }
                IrOp::LoadGlobal { dest, src } => {
                    buff.push(OpCode::LoadGlobal as u8);
                    buff.push(dest);
                    buff.push(src);
                }
                IrOp::LoadFun { dest, src } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstFun as u8);
                    buff.push(src);
                }
                IrOp::LoadObject { dest, src } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstObj as u8);
                    buff.push(src);
                }
                IrOp::SetProperty { key, val, obj } => {
                    buff.push(OpCode::SetProperty as u8);
                    buff.push(obj);
                    buff.push(key);
                    buff.push(val);
                }
                IrOp::SetPropertyDyn { key, val, obj } => {
                    buff.push(OpCode::SetPropertyDyn as u8);
                    buff.push(obj);
                    buff.push(key);
                    buff.push(val);
                }
                IrOp::GetProperty { dest, key, obj } => {
                    buff.push(OpCode::GetProperty as u8);
                    buff.push(dest);
                    buff.push(obj);
                    buff.push(key);
                }
                IrOp::GetPropertyDyn { dest, key, obj } => {
                    buff.push(OpCode::GetPropertyDyn as u8);
                    buff.push(dest);
                    buff.push(obj);
                    buff.push(key);
                }
                IrOp::Return { value } => {
                    buff.push(OpCode::Return as u8);
                    buff.push(value)
                }
                IrOp::Call { dest, what, args } => {
                    buff.push(OpCode::Call as u8);
                    buff.push(dest);
                    buff.push(what);
                    buff.push(args.len() as u8);

                    buff.extend_from_slice(&args);
                }
                IrOp::Binary {
                    dest,
                    op,
                    left,
                    right,
                } => {
                    buff.push(OpCode::Binary as u8);

                    let op_code = match op {
                        crate::parser::BinaryOperator::Add => 0,
                        crate::parser::BinaryOperator::Minus => 1,
                        crate::parser::BinaryOperator::Multiply => 2,
                        crate::parser::BinaryOperator::Divide => 3,
                        crate::parser::BinaryOperator::Equals => 4,
                        crate::parser::BinaryOperator::GreaterThan => 5,
                        crate::parser::BinaryOperator::LessThan => 6,
                        crate::parser::BinaryOperator::GreaterThanOrEqual => 7,
                        crate::parser::BinaryOperator::LessThanOrEqual => 8,
                        crate::parser::BinaryOperator::Modulo => 9,
                        crate::parser::BinaryOperator::BitAnd => 10,
                        crate::parser::BinaryOperator::BitOr => 11,
                        crate::parser::BinaryOperator::BitXor => 12,
                        crate::parser::BinaryOperator::BitSHL => 13,
                        crate::parser::BinaryOperator::BitSHR => 14,
                    };

                    buff.push(op_code);
                    buff.push(dest);
                    buff.push(left);
                    buff.push(right);
                }
                IrOp::Label(_) => (),
                IrOp::JumpNot { condition, target } => {
                    let target_offset = label_offsets[&target];

                    buff.push(OpCode::JumpNot as u8);
                    buff.push(condition);
                    buff.extend_from_slice(&(target_offset as u16).to_le_bytes());
                }
                IrOp::Jump { target } => {
                    let target_offset = label_offsets[&target];

                    buff.push(OpCode::Jump as u8);
                    buff.extend_from_slice(&(target_offset as u16).to_le_bytes());
                }
                IrOp::Inc { target } => {
                    buff.push(OpCode::Inc as u8);
                    buff.push(target);
                }

                IrOp::Dec { target } => {
                    buff.push(OpCode::Dec as u8);
                    buff.push(target);
                }
                IrOp::LoadEnumField {
                    enum_idx,
                    tag,
                    args,
                    dest,
                } => {
                    buff.push(OpCode::Load as u8);
                    buff.push(dest);
                    buff.push(OpCode::ConstEnum as u8);
                    buff.push(enum_idx);
                    buff.push(tag);

                    buff.push(args.len().try_into().unwrap());

                    for arg in args {
                        buff.extend_from_slice(&arg.0.to_le_bytes());
                        buff.push(arg.1);
                    }
                }
            }
        }

        buff
    }
}
