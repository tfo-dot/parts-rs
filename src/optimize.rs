use crate::{
    compiler::IrOp,
    parser::{Ast, BinaryOperator, Value},
};
use std::collections::{HashMap, HashSet};

pub struct AstOptimizer {
    inline_candidates: HashMap<String, (Vec<String>, Ast)>,
}

impl Default for AstOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl AstOptimizer {
    pub fn new() -> Self {
        Self {
            inline_candidates: HashMap::new(),
        }
    }

    pub fn collect_all(&mut self, nodes: &[Ast]) {
        for node in nodes {
            self.collect(node);
        }
    }

    pub fn optimize_all(&self, nodes: &mut [Ast]) -> bool {
        let mut changed = false;
        for node in nodes.iter_mut() {
            changed |= self.optimize(node);
        }
        changed
    }

    pub fn collect(&mut self, node: &Ast) {
        match node {
            Ast::Declare { name, value } => {
                if let Ast::Value(Value::Fun { args, body }) = &**value {
                    match &**body {
                        Ast::Block { code } if code.len() == 1 => {
                            if let Ast::Return { value: ret_val } = &code[0] {
                                self.inline_candidates
                                    .insert(name.clone(), (args.clone(), *ret_val.clone()));
                            }
                        }
                        Ast::Return { value: ret_val } => {
                            self.inline_candidates
                                .insert(name.clone(), (args.clone(), *ret_val.clone()));
                        }
                        _ => {}
                    }
                }
                self.collect(value);
            }
            Ast::Block { code } => {
                for stmt in code {
                    self.collect(stmt);
                }
            }
            Ast::Return { value } => self.collect(value),
            Ast::Raise { value } => self.collect(value),
            Ast::Set { name, value } => {
                self.collect(name);
                self.collect(value);
            }
            Ast::Call { what, args } => {
                self.collect(what);
                for arg in args {
                    self.collect(arg);
                }
            }
            Ast::Binary { left, right, .. } => {
                self.collect(left);
                self.collect(right);
            }
            Ast::If {
                then_branch,
                else_branch,
                condition,
            } => {
                self.collect(condition);
                self.collect(then_branch);
                if let Some(e) = else_branch {
                    self.collect(e);
                }
            }
            Ast::For { condition, body } => {
                self.collect(condition);
                self.collect(body);
            }
            Ast::ForEach { iterable, body, .. } => {
                self.collect(iterable);
                self.collect(body);
            }
            Ast::Dot {
                accessor, access, ..
            } => {
                self.collect(accessor);
                self.collect(access);
            }
            Ast::Object(pairs) => {
                for (k, v) in pairs {
                    self.collect(k);
                    self.collect(v);
                }
            }
            Ast::Value(Value::Fun { body, .. }) => self.collect(body),
            Ast::Value(Value::EnumField { fields, .. }) => {
                for f in fields {
                    self.collect(f);
                }
            }
            Ast::Match { target, arms } => {
                self.collect(target);
                for arm in arms {
                    self.collect(&arm.body);
                }
            }
            _ => {}
        }
    }
    pub fn optimize(&self, node: &mut Ast) -> bool {
        let mut changed = false;
        match node {
            Ast::Block { code } => {
                let mut cut_idx = None;
                for (idx, stmt) in code.iter_mut().enumerate() {
                    changed |= self.optimize(stmt);
                    if matches!(stmt, Ast::Return { .. } | Ast::Raise { .. }) {
                        cut_idx = Some(idx + 1);
                        break;
                    }
                }
                if let Some(cut) = cut_idx
                    && cut < code.len()
                {
                    code.truncate(cut);
                    changed = true;
                }
            }
            Ast::Declare { value, .. } => changed |= self.optimize(value),
            Ast::Return { value } => changed |= self.optimize(value),
            Ast::Raise { value } => changed |= self.optimize(value),
            Ast::Set { name, value } => {
                changed |= self.optimize(name);
                changed |= self.optimize(value);
            }
            Ast::Call { what, args } => {
                changed |= self.optimize(what);
                for arg in args.iter_mut() {
                    changed |= self.optimize(arg);
                }
            }
            Ast::Binary {
                left,
                right,
                operator,
            } => {
                changed |= self.optimize(left);
                changed |= self.optimize(right);

                if let Some(folded) = AstOptimizer::fold_binary(left, right, operator) {
                    *node = folded;
                    return true;
                }

                if let Ast::Value(Value::Int(0)) = **right {
                    match operator {
                        BinaryOperator::Add
                        | BinaryOperator::Minus
                        | BinaryOperator::BitOr
                        | BinaryOperator::BitXor => {
                            *node = *left.clone();
                            return true;
                        }
                        BinaryOperator::Multiply | BinaryOperator::BitAnd => {
                            *node = Ast::Value(Value::Int(0));
                            return true;
                        }
                        _ => {}
                    }
                }
                if let Ast::Value(Value::Int(0)) = **left {
                    match operator {
                        BinaryOperator::Add
                        | BinaryOperator::BitOr
                        | BinaryOperator::BitXor => {
                            *node = *right.clone();
                            return true;
                        }
                        BinaryOperator::Multiply | BinaryOperator::BitAnd => {
                            *node = Ast::Value(Value::Int(0));
                            return true;
                        }
                        _ => {}
                    }
                }
                if let Ast::Value(Value::Int(1)) = **right {
                    match operator {
                        BinaryOperator::Multiply | BinaryOperator::Divide => {
                            *node = *left.clone();
                            return true;
                        }
                        _ => {}
                    }
                }
                if let Ast::Value(Value::Int(1)) = **left
                    && matches!(operator, BinaryOperator::Multiply)
                {
                    *node = *right.clone();
                    return true;
                }

                if let Ast::Binary {
                    left: _,
                    right,
                    operator,
                } = node
                    && *operator == BinaryOperator::Modulo
                    && let Ast::Value(Value::Int(i)) = **right
                    && i > 0
                    && (i & (i - 1)) == 0
                {
                    *operator = BinaryOperator::BitAnd;
                    **right = Ast::Value(Value::Int(i - 1));
                    changed = true;
                }

                if let Ast::Binary {
                    left: _,
                    right,
                    operator,
                } = node
                    && *operator == BinaryOperator::Multiply
                    && let Ast::Value(Value::Int(i)) = **right
                    && i > 1
                    && (i & (i - 1)) == 0
                {
                    *operator = BinaryOperator::BitSHL;
                    **right = Ast::Value(Value::Int(i.trailing_zeros() as i64));
                    changed = true;
                }
            }
            Ast::If {
                then_branch,
                else_branch,
                condition,
            } => {
                changed |= self.optimize(condition);
                changed |= self.optimize(then_branch);
                if let Some(e) = else_branch {
                    changed |= self.optimize(e);
                }

                if let Ast::Value(Value::Bool(b)) = &**condition {
                    if *b {
                        *node = *then_branch.clone();
                    } else if let Some(else_b) = else_branch {
                        *node = *else_b.clone();
                    } else {
                        *node = Ast::Ignore;
                    }
                    return true;
                }
            }
            Ast::For { condition, body } => {
                changed |= self.optimize(condition);
                changed |= self.optimize(body);
            }
            Ast::ForEach { iterable, body, .. } => {
                changed |= self.optimize(iterable);
                changed |= self.optimize(body);
            }
            Ast::Dot {
                accessor, access, ..
            } => {
                changed |= self.optimize(accessor);
                changed |= self.optimize(access);
            }
            Ast::Object(pairs) => {
                for (k, v) in pairs.iter_mut() {
                    changed |= self.optimize(k);
                    changed |= self.optimize(v);
                }
            }
            Ast::Value(Value::Fun { body, .. }) => {
                changed |= self.optimize(body);
            }
            Ast::Value(Value::EnumField { fields, .. }) => {
                for f in fields.iter_mut() {
                    changed |= self.optimize(f);
                }
            }
            Ast::Match { target, arms } => {
                changed |= self.optimize(target);
                for arm in arms.iter_mut() {
                    changed |= self.optimize(&mut arm.body);
                }
            }
            _ => {}
        }

        if let Ast::Call { what, args } = node
            && let Ast::Value(Value::Ref(func_name)) = &**what
            && let Some((params, body_expr)) = self.inline_candidates.get(func_name)
            && params.len() == args.len()
        {
            let mut arg_map = HashMap::new();
            for (param, arg) in params.iter().zip(args.iter()) {
                arg_map.insert(param.clone(), arg.clone());
            }

            let mut inlined_body = body_expr.clone();
            self.substitute(&mut inlined_body, &arg_map);
            *node = inlined_body;
            changed = true;
        }

        changed
    }

    fn substitute(&self, node: &mut Ast, arg_map: &HashMap<String, Ast>) {
        if let Ast::Value(Value::Ref(var_name)) = node
            && let Some(replacement) = arg_map.get(var_name)
        {
            *node = replacement.clone();
            return;
        }

        match node {
            Ast::Binary { left, right, .. } => {
                self.substitute(left, arg_map);
                self.substitute(right, arg_map);
            }
            Ast::Call { what, args } => {
                self.substitute(what, arg_map);
                for arg in args.iter_mut() {
                    self.substitute(arg, arg_map);
                }
            }
            Ast::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.substitute(condition, arg_map);
                self.substitute(then_branch, arg_map);
                if let Some(e) = else_branch {
                    self.substitute(e, arg_map);
                }
            }
            Ast::Block { code } => {
                for stmt in code.iter_mut() {
                    self.substitute(stmt, arg_map);
                }
            }
            Ast::Set { name, value } => {
                self.substitute(name, arg_map);
                self.substitute(value, arg_map);
            }
            Ast::Dot {
                accessor, access, ..
            } => {
                self.substitute(accessor, arg_map);
                self.substitute(access, arg_map);
            }
            Ast::Object(pairs) => {
                for (k, v) in pairs.iter_mut() {
                    self.substitute(k, arg_map);
                    self.substitute(v, arg_map);
                }
            }
            Ast::Value(Value::Fun { body, .. }) => {
                self.substitute(body, arg_map);
            }
            Ast::Value(Value::EnumField { fields, .. }) => {
                for f in fields.iter_mut() {
                    self.substitute(f, arg_map);
                }
            }
            Ast::Match { target, arms } => {
                self.substitute(target, arg_map);
                for arm in arms.iter_mut() {
                    self.substitute(&mut arm.body, arg_map);
                }
            }
            _ => {}
        }
    }
    fn fold_binary(left: &Ast, right: &Ast, op: &BinaryOperator) -> Option<Ast> {
        if let (Ast::Value(Value::Int(l)), Ast::Value(Value::Int(r))) = (left, right) {
            let res = match op {
                BinaryOperator::Add => l + r,
                BinaryOperator::Minus => l - r,
                BinaryOperator::Multiply => l * r,
                BinaryOperator::Divide => {
                    if *r != 0 {
                        l / r
                    } else {
                        return None;
                    }
                }
                BinaryOperator::BitAnd => l & r,
                BinaryOperator::BitOr => l | r,
                BinaryOperator::BitXor => l ^ r,
                BinaryOperator::Equals => return Some(Ast::Value(Value::Bool(l == r))),
                BinaryOperator::GreaterThan => return Some(Ast::Value(Value::Bool(l > r))),
                BinaryOperator::LessThan => return Some(Ast::Value(Value::Bool(l < r))),
                BinaryOperator::GreaterThanOrEqual => return Some(Ast::Value(Value::Bool(l >= r))),
                BinaryOperator::LessThanOrEqual => return Some(Ast::Value(Value::Bool(l <= r))),
                BinaryOperator::Modulo => {
                    if *r != 0 {
                        l % r
                    } else {
                        return None;
                    }
                }
                BinaryOperator::BitSHL => l << r,
                BinaryOperator::BitSHR => l >> r,
            };
            return Some(Ast::Value(Value::Int(res)));
        }

        if let (Ast::Value(Value::Double(l)), Ast::Value(Value::Double(r))) = (left, right) {
            let res = match op {
                BinaryOperator::Add => l + r,
                BinaryOperator::Minus => l - r,
                BinaryOperator::Multiply => l * r,
                BinaryOperator::Divide => {
                    if *r != 0.0 {
                        l / r
                    } else {
                        return None;
                    }
                }
                BinaryOperator::Equals => return Some(Ast::Value(Value::Bool(l == r))),
                BinaryOperator::GreaterThan => return Some(Ast::Value(Value::Bool(l > r))),
                BinaryOperator::LessThan => return Some(Ast::Value(Value::Bool(l < r))),
                BinaryOperator::GreaterThanOrEqual => return Some(Ast::Value(Value::Bool(l >= r))),
                BinaryOperator::LessThanOrEqual => return Some(Ast::Value(Value::Bool(l <= r))),
                _ => return None,
            };
            return Some(Ast::Value(Value::Double(res)));
        }

        if let (Ast::Value(Value::String(l)), Ast::Value(Value::String(r))) = (left, right) {
            if matches!(op, BinaryOperator::Add) {
                let mut s = l.clone();
                s.push_str(r);
                return Some(Ast::Value(Value::String(s)));
            }
            if matches!(op, BinaryOperator::Equals) {
                return Some(Ast::Value(Value::Bool(l == r)));
            }
        }

        if let (Ast::Value(Value::Bool(l)), Ast::Value(Value::Bool(r))) = (left, right)
            && matches!(op, BinaryOperator::Equals)
        {
            return Some(Ast::Value(Value::Bool(l == r)));
        }

        None
    }
}

pub struct IrOptimizer;

impl IrOptimizer {
    pub fn optimize(ir: Vec<IrOp>) -> Vec<IrOp> {
        let mut current_ir = ir;

        loop {
            let start_len = current_ir.len();

            current_ir = Self::peephole_pass(current_ir);
            current_ir = Self::copy_propagation_pass(current_ir);
            current_ir = Self::inc_dec_pass(current_ir);
            current_ir = Self::state_and_dead_store_pass(current_ir);
            current_ir = Self::unreachable_code_pass(current_ir);
            current_ir = Self::jump_threading_pass(current_ir);

            //TODO swap to bool check, like in AST
            if current_ir.len() == start_len {
                break;
            }
        }
        current_ir
    }

    fn peephole_pass(ir: Vec<IrOp>) -> Vec<IrOp> {
        let mut optimized = Vec::with_capacity(ir.len());
        let mut i = 0;

        while i < ir.len() {
            if i + 1 < ir.len() {
                let mut op1 = ir[i].clone();
                let op2 = &ir[i + 1];

                if let IrOp::LoadReg {
                    dest: final_dest,
                    src: load_src,
                } = op2
                {
                    let mut merged = false;

                    match &mut op1 {
                        IrOp::Binary { dest, .. }
                        | IrOp::Call { dest, .. }
                        | IrOp::GetProperty { dest, .. }
                        | IrOp::GetPropertyDyn { dest, .. }
                        | IrOp::LoadInt { dest, .. }
                        | IrOp::LoadConst { dest, .. }
                        | IrOp::LoadObject { dest, .. }
                        | IrOp::LoadNative { dest, .. }
                        | IrOp::LoadFun { dest, .. }
                        | IrOp::LoadEnumField { dest, .. }
                        | IrOp::MatchEnum { dest, .. }
                            if *dest == *load_src =>
                        {
                            *dest = *final_dest;
                            merged = true;
                        }
                        _ => {}
                    }

                    if merged {
                        optimized.push(op1);
                        i += 2;
                        continue;
                    }
                }

                if let (IrOp::LoadInt { dest: d1, .. }, IrOp::LoadInt { dest: d2, .. }) =
                    (&op1, op2)
                    && d1 == d2
                {
                    i += 1;
                    continue;
                }

                if let (IrOp::Jump { target: t1 }, IrOp::Label(t2)) = (&op1, op2)
                    && t1 == t2
                {
                    optimized.push(op2.clone());
                    i += 2;
                    continue;
                }
            }

            optimized.push(ir[i].clone());
            i += 1;
        }

        optimized
    }

    fn state_and_dead_store_pass(ir: Vec<IrOp>) -> Vec<IrOp> {
        let mut optimized = Vec::with_capacity(ir.len());
        let mut known_ints: HashMap<u8, i64> = HashMap::new();
        let mut i = 0;

        while i < ir.len() {
            let op = &ir[i];
            let mut keep = true;

            if matches!(
                op,
                IrOp::Label(_) | IrOp::Jump { .. } | IrOp::JumpNot { .. }
            ) {
                known_ints.clear();
            }

            if let IrOp::LoadInt { dest, val } = op
                && known_ints.get(dest) == Some(val)
            {
                keep = false;
            }

            if keep && let IrOp::LoadInt { dest, .. } = op {
                let mut is_dead = false;

                let limit = std::cmp::min(i + 15, ir.len());
                for future_op in ir.iter().take(limit).skip(i + 1) {
                    if matches!(
                        future_op,
                        IrOp::Label(_) | IrOp::Jump { .. } | IrOp::JumpNot { .. }
                    ) {
                        break;
                    }

                    let reads_dest = match future_op {
                        IrOp::Binary { left, right, .. } => *left == *dest || *right == *dest,
                        IrOp::GetProperty { obj, .. } => *obj == *dest,
                        IrOp::GetPropertyDyn { obj, key, .. } => *obj == *dest || *key == *dest,
                        IrOp::SetPropertyDyn { obj, key, val } => {
                            *obj == *dest || *key == *dest || *val == *dest
                        }
                        IrOp::LoadReg { src, .. } => *src == *dest,
                        IrOp::SetProperty { obj, val, .. } => *obj == *dest || *val == *dest,
                        IrOp::Call { what, args, .. } | IrOp::TailCall { what, args } => {
                            *what == *dest || args.contains(dest)
                        }
                        IrOp::LoadEnumField { args, .. } => args.iter().any(|(_, reg)| reg == dest),
                        IrOp::MatchEnum { src, .. } => *src == *dest,
                        _ => false,
                    };

                    if reads_dest {
                        break;
                    }

                    let writes_dest = match future_op {
                        IrOp::LoadInt { dest: d, .. }
                        | IrOp::LoadBool { dest: d, .. }
                        | IrOp::LoadConst { dest: d, .. }
                        | IrOp::LoadObject { dest: d, .. }
                        | IrOp::LoadNative { dest: d, .. }
                        | IrOp::LoadFun { dest: d, .. }
                        | IrOp::LoadReg { dest: d, .. }
                        | IrOp::Binary { dest: d, .. }
                        | IrOp::GetProperty { dest: d, .. }
                        | IrOp::GetPropertyDyn { dest: d, .. }
                        | IrOp::Call { dest: d, .. }
                        | IrOp::LoadEnumField { dest: d, .. }
                        | IrOp::MatchEnum { dest: d, .. } => *d == *dest,
                        _ => false,
                    };

                    if writes_dest {
                        is_dead = true;
                        break;
                    }
                }

                if is_dead {
                    keep = false;
                }
            }

            if keep {
                let writes_to = match op {
                    IrOp::LoadInt { dest, .. }
                    | IrOp::LoadGlobal { dest, .. }
                    | IrOp::LoadDouble { dest, .. }
                    | IrOp::LoadBool { dest, .. }
                    | IrOp::LoadConst { dest, .. }
                    | IrOp::LoadObject { dest, .. }
                    | IrOp::LoadNative { dest, .. }
                    | IrOp::LoadFun { dest, .. }
                    | IrOp::LoadReg { dest, .. }
                    | IrOp::Binary { dest, .. }
                    | IrOp::GetProperty { dest, .. }
                    | IrOp::GetPropertyDyn { dest, .. }
                    | IrOp::Call { dest, .. }
                    | IrOp::LoadEnumField { dest, .. }
                    | IrOp::MatchEnum { dest, .. } => Some(*dest),
                    _ => None,
                };

                if let Some(dest) = writes_to {
                    if let IrOp::LoadInt { val, .. } = op {
                        known_ints.insert(dest, *val);
                    } else {
                        known_ints.remove(&dest);
                    }
                }

                optimized.push(op.clone());
            }

            i += 1;
        }

        optimized
    }

    fn inc_dec_pass(ir: Vec<IrOp>) -> Vec<IrOp> {
        let mut optimized = Vec::with_capacity(ir.len());
        let mut i = 0;

        while i < ir.len() {
            if i + 1 < ir.len() {
                let op1 = &ir[i];
                let op2 = &ir[i + 1];

                if let IrOp::LoadInt {
                    dest: temp_reg,
                    val,
                } = op1
                    && let IrOp::Binary {
                        dest: target_reg,
                        op,
                        left,
                        right,
                    } = op2
                {
                    let is_target_left = target_reg == left && temp_reg == right;
                    let is_target_right = target_reg == right && temp_reg == left;

                    let is_add = matches!(op, BinaryOperator::Add);
                    let is_sub = matches!(op, BinaryOperator::Minus);

                    let valid_add = is_add && (is_target_left || is_target_right);
                    let valid_sub = is_sub && is_target_left;

                    if valid_add || valid_sub {
                        let mut replaced = false;

                        if (valid_add && *val == 1) || (valid_sub && *val == -1) {
                            optimized.push(IrOp::Inc {
                                target: *target_reg,
                            });
                            replaced = true;
                        } else if (valid_sub && *val == 1) || (valid_add && *val == -1) {
                            optimized.push(IrOp::Dec {
                                target: *target_reg,
                            });
                            replaced = true;
                        }

                        if replaced {
                            i += 2;
                            continue;
                        }
                    }
                }
            }

            optimized.push(ir[i].clone());
            i += 1;
        }

        optimized
    }
    fn unreachable_code_pass(ir: Vec<IrOp>) -> Vec<IrOp> {
        let mut optimized = Vec::with_capacity(ir.len());
        let mut skipping = false;
        for op in ir {
            if skipping {
                if matches!(op, IrOp::Label(_)) {
                    skipping = false;
                    optimized.push(op);
                }
                continue;
            }
            if matches!(op, IrOp::Jump { .. } | IrOp::Return { .. } | IrOp::TailCall { .. }) {
                skipping = true;
            }
            optimized.push(op);
        }
        optimized
    }
    fn copy_propagation_pass(ir: Vec<IrOp>) -> Vec<IrOp> {
        let mut optimized = Vec::with_capacity(ir.len());
        let mut copies: HashMap<u8, u8> = HashMap::new();

        for mut op in ir {
            if matches!(
                op,
                IrOp::Label(_)
                    | IrOp::Jump { .. }
                    | IrOp::JumpNot { .. }
                    | IrOp::Call { .. }
                    | IrOp::TailCall { .. }
            ) {
                copies.clear();
            }

            match &mut op {
                IrOp::Binary { left, right, .. } => {
                    if let Some(&src) = copies.get(left) {
                        *left = src;
                    }
                    if let Some(&src) = copies.get(right) {
                        *right = src;
                    }
                }
                IrOp::Call { what, args, .. } | IrOp::TailCall { what, args } => {
                    if let Some(&src) = copies.get(what) {
                        *what = src;
                    }
                    for arg in args.iter_mut() {
                        if let Some(&src) = copies.get(arg) {
                            *arg = src;
                        }
                    }
                }
                IrOp::GetProperty { obj, .. } => {
                    if let Some(&src) = copies.get(obj) {
                        *obj = src;
                    }
                }
                IrOp::GetPropertyDyn { obj, key, .. } => {
                    if let Some(&src) = copies.get(obj) {
                        *obj = src;
                    }
                    if let Some(&src) = copies.get(key) {
                        *key = src;
                    }
                }
                IrOp::SetProperty { obj, val, .. } => {
                    if let Some(&src) = copies.get(obj) {
                        *obj = src;
                    }
                    if let Some(&src) = copies.get(val) {
                        *val = src;
                    }
                }
                IrOp::SetPropertyDyn { obj, key, val } => {
                    if let Some(&src) = copies.get(obj) {
                        *obj = src;
                    }
                    if let Some(&src) = copies.get(key) {
                        *key = src;
                    }
                    if let Some(&src) = copies.get(val) {
                        *val = src;
                    }
                }
                IrOp::Return { value } => {
                    if let Some(&src) = copies.get(value) {
                        *value = src;
                    }
                }
                IrOp::JumpNot { condition, .. } => {
                    if let Some(&src) = copies.get(condition) {
                        *condition = src;
                    }
                }
                IrOp::MatchEnum { src, .. } => {
                    if let Some(&s) = copies.get(src) {
                        *src = s;
                    }
                }
                _ => {}
            }

            if let IrOp::LoadReg { dest, src } = op {
                if dest != src {
                    copies.insert(dest, src);
                }
            } else if let Some(dest) = Self::writes_dest(&op) {
                copies.remove(&dest);
                copies.retain(|_, &mut v| v != dest);
            }

            optimized.push(op);
        }
        optimized
    }

    fn writes_dest(op: &IrOp) -> Option<u8> {
        match op {
            IrOp::LoadInt { dest, .. }
            | IrOp::LoadGlobal { dest, .. }
            | IrOp::LoadDouble { dest, .. }
            | IrOp::LoadBool { dest, .. }
            | IrOp::LoadConst { dest, .. }
            | IrOp::LoadObject { dest, .. }
            | IrOp::LoadNative { dest, .. }
            | IrOp::LoadFun { dest, .. }
            | IrOp::LoadReg { dest, .. }
            | IrOp::Binary { dest, .. }
            | IrOp::GetProperty { dest, .. }
            | IrOp::GetPropertyDyn { dest, .. }
            | IrOp::Call { dest, .. }
            | IrOp::LoadEnumField { dest, .. }
            | IrOp::MatchEnum { dest, .. } => Some(*dest),
            _ => None,
        }
    }

    fn jump_threading_pass(ir: Vec<IrOp>) -> Vec<IrOp> {
        let mut jump_map: HashMap<usize, usize> = HashMap::new();
        let mut i = 0;
        while i < ir.len() {
            if let IrOp::Label(l1) = ir[i]
                && i + 1 < ir.len()
                && let IrOp::Jump { target: l2 } = ir[i + 1]
            {
                jump_map.insert(l1, l2);
            }
            i += 1;
        }

        if jump_map.is_empty() {
            return ir;
        }

        let mut resolved_map = HashMap::new();
        for (&start, &next) in &jump_map {
            let mut target = next;
            let mut visited = HashSet::new();
            visited.insert(start);
            while let Some(&further) = jump_map.get(&target) {
                if visited.contains(&further) {
                    break;
                }
                visited.insert(further);
                target = further;
            }
            resolved_map.insert(start, target);
        }

        let mut optimized = Vec::with_capacity(ir.len());
        for mut op in ir {
            match &mut op {
                IrOp::Jump { target } => {
                    if let Some(&final_t) = resolved_map.get(target) {
                        *target = final_t;
                    }
                }
                IrOp::JumpNot { target, .. } => {
                    if let Some(&final_t) = resolved_map.get(target) {
                        *target = final_t;
                    }
                }
                _ => {}
            }
            optimized.push(op);
        }
        optimized
    }
}
