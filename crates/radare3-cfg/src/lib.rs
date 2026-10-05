#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use radare3_types::{Address, BlockId, FunctionId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start: Address,
    pub end: Address,
    pub successors: Vec<BlockId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Function {
    pub id: FunctionId,
    pub entry: Address,
    pub blocks: Vec<BlockId>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlFlowGraph {
    pub functions: BTreeMap<FunctionId, Function>,
    pub blocks: BTreeMap<BlockId, BasicBlock>,
}
