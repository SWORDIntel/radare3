#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use radare3_arch::{Decoder, FlowKind};
use radare3_cfg::{BasicBlock, ControlFlowGraph, Function};
use radare3_image::BinaryImage;
use radare3_types::{Address, BlockId, Fidelity, FunctionId, XrefId};
use radare3_xref::{Xref, XrefKind};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisOptions {
    pub entrypoints: Vec<Address>,
    pub max_instructions: Option<u64>,
    pub deterministic: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            entrypoints: Vec::new(),
            max_instructions: None,
            deterministic: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisResult {
    pub cfg: ControlFlowGraph,
    pub xrefs: Vec<Xref>,
    pub fidelity: Fidelity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnalysisError {
    UnsupportedArchitecture,
    BudgetExceeded,
    InternalInvariant,
}

pub trait Analyzer: Send + Sync {
    fn analyze(
        &self,
        image: &BinaryImage,
        options: &AnalysisOptions,
    ) -> Result<AnalysisResult, AnalysisError>;
}

#[derive(Clone, Debug)]
struct TempBlock {
    start: Address,
    end: Address,
    successors: BTreeSet<Address>,
}

#[derive(Clone, Debug)]
pub struct RecursiveAnalyzer<D> {
    decoder: D,
}

impl<D> RecursiveAnalyzer<D> {
    pub const fn new(decoder: D) -> Self {
        Self { decoder }
    }
}

impl<D: Decoder> Analyzer for RecursiveAnalyzer<D> {
    fn analyze(
        &self,
        image: &BinaryImage,
        options: &AnalysisOptions,
    ) -> Result<AnalysisResult, AnalysisError> {
        let mut function_seeds = BTreeSet::new();
        if options.entrypoints.is_empty() {
            function_seeds.extend(image.function_seeds.iter().map(|seed| seed.address));
            if function_seeds.is_empty() {
                if let Some(entry) = image.entry_point {
                    function_seeds.insert(entry);
                }
            }
        } else {
            function_seeds.extend(options.entrypoints.iter().copied());
        }

        let mut processed_functions = BTreeSet::new();
        let mut function_blocks: BTreeMap<Address, BTreeSet<Address>> = BTreeMap::new();
        let mut blocks: BTreeMap<Address, TempBlock> = BTreeMap::new();
        let mut raw_xrefs = BTreeSet::new();
        let mut decoded_instructions = 0_u64;
        let mut fidelity = Fidelity::Heuristic;

        while let Some(function_entry) = function_seeds.pop_first() {
            if !processed_functions.insert(function_entry) {
                continue;
            }
            if !is_executable_file_address(image, function_entry) {
                continue;
            }

            let mut work = BTreeSet::from([function_entry]);
            let members = function_blocks.entry(function_entry).or_default();

            while let Some(block_start) = work.pop_first() {
                if !is_executable_file_address(image, block_start) {
                    continue;
                }
                if !members.insert(block_start) {
                    continue;
                }

                if let Some(existing) = blocks.get(&block_start) {
                    work.extend(existing.successors.iter().copied());
                    continue;
                }

                let mut current = block_start;
                let mut successors = BTreeSet::new();
                let end = loop {
                    if current != block_start && blocks.contains_key(&current) {
                        successors.insert(current);
                        break current;
                    }

                    if let Some(limit) = options.max_instructions {
                        if decoded_instructions >= limit {
                            return Err(AnalysisError::BudgetExceeded);
                        }
                    }

                    let Some(bytes) = image.bytes_at(current, 15) else {
                        fidelity = Fidelity::Incomplete;
                        break current;
                    };

                    let decoded = match self.decoder.decode(current, bytes) {
                        Ok(decoded) => decoded,
                        Err(_) => {
                            fidelity = Fidelity::Incomplete;
                            break current;
                        }
                    };

                    if decoded.length == 0 {
                        return Err(AnalysisError::InternalInvariant);
                    }

                    decoded_instructions = decoded_instructions.saturating_add(1);
                    let Some(next_raw) = current.0.checked_add(u64::from(decoded.length)) else {
                        fidelity = Fidelity::Incomplete;
                        break current;
                    };
                    let next = Address(next_raw);

                    match decoded.flow {
                        FlowKind::Fallthrough | FlowKind::Unknown => {
                            current = next;
                        }
                        FlowKind::Call => {
                            if let Some(target) = decoded.target {
                                raw_xrefs.insert((decoded.address, target, XrefKindKey::Call));
                                if is_executable_file_address(image, target) {
                                    function_seeds.insert(target);
                                }
                            }
                            current = next;
                        }
                        FlowKind::Branch => {
                            if let Some(target) = decoded.target {
                                raw_xrefs.insert((decoded.address, target, XrefKindKey::Code));
                                if is_executable_file_address(image, target) {
                                    successors.insert(target);
                                    work.insert(target);
                                }
                            }
                            break next;
                        }
                        FlowKind::ConditionalBranch => {
                            if let Some(target) = decoded.target {
                                raw_xrefs.insert((decoded.address, target, XrefKindKey::Code));
                                if is_executable_file_address(image, target) {
                                    successors.insert(target);
                                    work.insert(target);
                                }
                            }
                            if is_executable_file_address(image, next) {
                                successors.insert(next);
                                work.insert(next);
                            }
                            break next;
                        }
                        FlowKind::Return | FlowKind::Trap => break next,
                    }
                };

                blocks.insert(
                    block_start,
                    TempBlock {
                        start: block_start,
                        end,
                        successors,
                    },
                );
            }
        }

        let block_ids: BTreeMap<Address, BlockId> = blocks
            .keys()
            .copied()
            .enumerate()
            .map(|(index, address)| {
                u32::try_from(index)
                    .map(|id| (address, BlockId(id)))
                    .map_err(|_| AnalysisError::InternalInvariant)
            })
            .collect::<Result<_, _>>()?;

        let mut cfg = ControlFlowGraph::default();

        for (start, block) in &blocks {
            let id = *block_ids
                .get(start)
                .ok_or(AnalysisError::InternalInvariant)?;
            let successors = block
                .successors
                .iter()
                .filter_map(|address| block_ids.get(address).copied())
                .collect();

            cfg.blocks.insert(
                id,
                BasicBlock {
                    id,
                    start: block.start,
                    end: block.end,
                    successors,
                },
            );
        }

        for (index, (entry, members)) in function_blocks.iter().enumerate() {
            let id =
                FunctionId(u32::try_from(index).map_err(|_| AnalysisError::InternalInvariant)?);
            let function_block_ids = members
                .iter()
                .filter_map(|address| block_ids.get(address).copied())
                .collect();

            cfg.functions.insert(
                id,
                Function {
                    id,
                    entry: *entry,
                    blocks: function_block_ids,
                    name: image
                        .preferred_function_name(*entry)
                        .map(str::to_owned)
                        .or_else(|| Some(format!("sub_{:x}", entry.0))),
                },
            );
        }

        let xrefs = raw_xrefs
            .into_iter()
            .enumerate()
            .map(|(index, (from, to, kind))| {
                Ok(Xref {
                    id: XrefId(u32::try_from(index).map_err(|_| AnalysisError::InternalInvariant)?),
                    from,
                    to,
                    kind: kind.into(),
                })
            })
            .collect::<Result<Vec<_>, AnalysisError>>()?;

        Ok(AnalysisResult {
            cfg,
            xrefs,
            fidelity,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum XrefKindKey {
    Call,
    Code,
}

impl From<XrefKindKey> for XrefKind {
    fn from(value: XrefKindKey) -> Self {
        match value {
            XrefKindKey::Call => Self::Call,
            XrefKindKey::Code => Self::Code,
        }
    }
}

fn is_executable_file_address(image: &BinaryImage, address: Address) -> bool {
    image
        .segments
        .iter()
        .any(|segment| segment.permissions.execute && segment.contains_file_address(address))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use radare3_image::{FunctionSeed, FunctionSeedKind, Permissions, Segment};
    use radare3_types::{Architecture, BinaryFormat};

    use super::*;

    #[derive(Clone, Copy)]
    struct TestDecoder;

    impl Decoder for TestDecoder {
        fn decode(
            &self,
            address: Address,
            bytes: &[u8],
        ) -> Result<radare3_arch::DecodedInstruction, radare3_arch::DecodeError> {
            use radare3_arch::{DecodeError, DecodedInstruction};

            let opcode = *bytes.first().ok_or(DecodeError::InsufficientBytes)?;
            let decoded = match (address.0, opcode) {
                (0x1000, 0xe8) => DecodedInstruction {
                    address,
                    length: 5,
                    flow: FlowKind::Call,
                    target: Some(Address(0x1010)),
                },
                (0x1005, 0x75) => DecodedInstruction {
                    address,
                    length: 2,
                    flow: FlowKind::ConditionalBranch,
                    target: Some(Address(0x100a)),
                },
                (_, 0xc3) => DecodedInstruction {
                    address,
                    length: 1,
                    flow: FlowKind::Return,
                    target: None,
                },
                _ => return Err(DecodeError::InvalidInstruction),
            };
            Ok(decoded)
        }
    }

    fn test_image() -> BinaryImage {
        let mut bytes = vec![0_u8; 0x20];
        bytes[0x00] = 0xe8;
        bytes[0x05] = 0x75;
        bytes[0x07] = 0xc3;
        bytes[0x0a] = 0xc3;
        bytes[0x10] = 0xc3;

        BinaryImage::new(
            Arc::from(bytes),
            BinaryFormat::Raw,
            Architecture::X86_64,
            Address(0x1000),
            Some(Address(0x1000)),
            vec![Segment {
                name: "text".to_string(),
                address: Address(0x1000),
                file_offset: 0,
                file_size: 0x20,
                memory_size: 0x20,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
        )
        .with_function_seeds(vec![FunctionSeed {
            address: Address(0x1010),
            kind: FunctionSeedKind::Symbol,
            name: Some("helper".to_string()),
        }])
    }

    #[test]
    fn discovers_functions_blocks_and_xrefs_deterministically() -> Result<(), AnalysisError> {
        let analyzer = RecursiveAnalyzer::new(TestDecoder);
        let image = test_image();
        let first = analyzer.analyze(&image, &AnalysisOptions::default())?;
        let second = analyzer.analyze(&image, &AnalysisOptions::default())?;

        assert_eq!(first, second);
        assert_eq!(first.cfg.functions.len(), 2);
        assert_eq!(first.cfg.blocks.len(), 4);
        assert_eq!(first.xrefs.len(), 2);

        let entries: Vec<_> = first
            .cfg
            .functions
            .values()
            .map(|function| function.entry)
            .collect();
        assert_eq!(entries, vec![Address(0x1000), Address(0x1010)]);

        let helper = first
            .cfg
            .functions
            .values()
            .find(|function| function.entry == Address(0x1010))
            .ok_or(AnalysisError::InternalInvariant)?;
        assert_eq!(helper.name.as_deref(), Some("helper"));

        let starts: Vec<_> = first.cfg.blocks.values().map(|block| block.start).collect();
        assert_eq!(
            starts,
            vec![
                Address(0x1000),
                Address(0x1007),
                Address(0x100a),
                Address(0x1010)
            ]
        );

        assert_eq!(first.xrefs[0].from, Address(0x1000));
        assert_eq!(first.xrefs[0].to, Address(0x1010));
        assert_eq!(first.xrefs[0].kind, XrefKind::Call);
        assert_eq!(first.xrefs[1].from, Address(0x1005));
        assert_eq!(first.xrefs[1].to, Address(0x100a));
        assert_eq!(first.xrefs[1].kind, XrefKind::Code);

        Ok(())
    }

    #[test]
    fn enforces_instruction_budget() {
        let analyzer = RecursiveAnalyzer::new(TestDecoder);
        let image = test_image();
        let options = AnalysisOptions {
            max_instructions: Some(1),
            ..AnalysisOptions::default()
        };

        assert_eq!(
            analyzer.analyze(&image, &options),
            Err(AnalysisError::BudgetExceeded)
        );
    }
}
