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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FunctionIndex {
    by_entry: BTreeMap<Address, FunctionId>,
}

impl FunctionIndex {
    pub fn build(cfg: &ControlFlowGraph) -> Self {
        let by_entry = cfg
            .functions
            .values()
            .map(|function| (function.entry, function.id))
            .collect();

        Self { by_entry }
    }

    pub fn function_id(&self, entry: Address) -> Option<FunctionId> {
        self.by_entry.get(&entry).copied()
    }

    pub fn function<'a>(
        &self,
        cfg: &'a ControlFlowGraph,
        entry: Address,
    ) -> Option<&'a Function> {
        self.function_id(entry)
            .and_then(|id| cfg.functions.get(&id))
    }

    pub fn len(&self) -> usize {
        self.by_entry.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_entry.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cfg() -> ControlFlowGraph {
        ControlFlowGraph {
            functions: BTreeMap::from([
                (
                    FunctionId(0),
                    Function {
                        id: FunctionId(0),
                        entry: Address(0x1000),
                        blocks: vec![BlockId(0)],
                        name: Some("entry".to_string()),
                    },
                ),
                (
                    FunctionId(1),
                    Function {
                        id: FunctionId(1),
                        entry: Address(0x2000),
                        blocks: vec![BlockId(1)],
                        name: Some("helper".to_string()),
                    },
                ),
            ]),
            blocks: BTreeMap::from([
                (
                    BlockId(0),
                    BasicBlock {
                        id: BlockId(0),
                        start: Address(0x1000),
                        end: Address(0x1010),
                        successors: Vec::new(),
                    },
                ),
                (
                    BlockId(1),
                    BasicBlock {
                        id: BlockId(1),
                        start: Address(0x2000),
                        end: Address(0x2010),
                        successors: Vec::new(),
                    },
                ),
            ]),
        }
    }

    #[test]
    fn resolves_functions_by_entry_address() {
        let cfg = sample_cfg();
        let index = FunctionIndex::build(&cfg);

        assert_eq!(index.len(), 2);
        assert!(!index.is_empty());
        assert_eq!(index.function_id(Address(0x1000)), Some(FunctionId(0)));
        assert_eq!(index.function_id(Address(0x2000)), Some(FunctionId(1)));
        assert_eq!(index.function_id(Address(0x3000)), None);
        assert_eq!(
            index
                .function(&cfg, Address(0x2000))
                .and_then(|function| function.name.as_deref()),
            Some("helper")
        );
    }

    #[test]
    fn empty_cfg_produces_empty_index() {
        let cfg = ControlFlowGraph::default();
        let index = FunctionIndex::build(&cfg);

        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert_eq!(index.function(Address(0x1000)), None);
    }
}
