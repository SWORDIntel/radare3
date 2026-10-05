#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::Excluded;

use radare3_arch::{Decoder, FlowKind};
use radare3_cfg::{BasicBlock, ControlFlowGraph, Function};
use radare3_image::BinaryImage;
use radare3_types::{Address, BlockId, Fidelity, FunctionId, XrefId};
use radare3_xref::{Xref, XrefKind};
use rayon::prelude::*;

const MAX_DENSE_EXECUTABLE_BYTES: usize = 64 * 1024 * 1024;

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct TempBlock {
    start: Address,
    end: Address,
    successors: BTreeSet<Address>,
}

#[derive(Clone, Debug)]
struct FunctionDiscovery {
    entry: Address,
    blocks: BTreeMap<Address, TempBlock>,
    xrefs: BTreeSet<(Address, Address, XrefKindKey)>,
    callees: BTreeSet<Address>,
    fidelity: Fidelity,
    decoded_instructions: u64,
}

#[derive(Clone, Debug)]
struct ExecutableRange {
    start: Address,
    end: u64,
    dense_base: usize,
}

#[derive(Clone, Debug)]
struct ExecutableAddressIndex {
    ranges: Vec<ExecutableRange>,
    total_bytes: usize,
    dense_enabled: bool,
}

impl ExecutableAddressIndex {
    fn new(image: &BinaryImage) -> Self {
        let mut ranges = Vec::new();
        let mut total_bytes = 0_usize;
        let mut dense_enabled = true;

        for segment in image
            .segments
            .iter()
            .filter(|segment| segment.permissions.execute && segment.file_size != 0)
        {
            let Some(end) = segment.address.0.checked_add(segment.file_size) else {
                dense_enabled = false;
                continue;
            };
            let Ok(length) = usize::try_from(segment.file_size) else {
                dense_enabled = false;
                continue;
            };
            let Some(next_total) = total_bytes.checked_add(length) else {
                dense_enabled = false;
                continue;
            };

            ranges.push(ExecutableRange {
                start: segment.address,
                end,
                dense_base: total_bytes,
            });
            total_bytes = next_total;
        }

        dense_enabled &= total_bytes <= MAX_DENSE_EXECUTABLE_BYTES;

        Self {
            ranges,
            total_bytes,
            dense_enabled,
        }
    }

    fn index(&self, address: Address) -> Option<usize> {
        self.ranges.iter().find_map(|range| {
            if address.0 < range.start.0 || address.0 >= range.end {
                return None;
            }

            let delta = address.0.checked_sub(range.start.0)?;
            let delta = usize::try_from(delta).ok()?;
            range.dense_base.checked_add(delta)
        })
    }
}

#[derive(Debug)]
enum VisitedBlocks {
    Dense {
        words: Vec<u64>,
        touched_words: Vec<usize>,
    },
    Sparse(BTreeSet<Address>),
}

impl VisitedBlocks {
    fn new(index: &ExecutableAddressIndex) -> Self {
        if index.dense_enabled {
            let word_count = index.total_bytes.saturating_add(63) / 64;
            Self::Dense {
                words: vec![0; word_count],
                touched_words: Vec::new(),
            }
        } else {
            Self::Sparse(BTreeSet::new())
        }
    }

    fn reset(&mut self) {
        match self {
            Self::Dense {
                words,
                touched_words,
            } => {
                for word in touched_words.drain(..) {
                    words[word] = 0;
                }
            }
            Self::Sparse(addresses) => addresses.clear(),
        }
    }

    fn insert(&mut self, index: &ExecutableAddressIndex, address: Address) -> bool {
        match self {
            Self::Dense {
                words,
                touched_words,
            } => {
                let Some(bit_index) = index.index(address) else {
                    return false;
                };
                let word_index = bit_index / 64;
                let bit = 1_u64 << (bit_index % 64);
                let word = &mut words[word_index];

                if *word & bit != 0 {
                    return false;
                }
                if *word == 0 {
                    touched_words.push(word_index);
                }
                *word |= bit;
                true
            }
            Self::Sparse(addresses) => addresses.insert(address),
        }
    }
}

#[derive(Debug)]
struct WorkerArena {
    visited: VisitedBlocks,
}

impl WorkerArena {
    fn new(index: &ExecutableAddressIndex) -> Self {
        Self {
            visited: VisitedBlocks::new(index),
        }
    }

    fn reset(&mut self) {
        self.visited.reset();
    }
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
        let index = ExecutableAddressIndex::new(image);
        let mut arena = WorkerArena::new(&index);
        let mut pending = initial_function_seeds(image, options);
        let mut processed = BTreeSet::new();
        let mut discoveries = Vec::new();
        let mut decoded_instructions = 0_u64;

        while let Some(entry) = pending.pop_first() {
            if !processed.insert(entry) || !is_executable_file_address(image, entry) {
                continue;
            }

            let discovery = discover_function(
                &self.decoder,
                image,
                &index,
                &mut arena,
                entry,
                options.max_instructions,
            )?;
            charge_budget(
                &mut decoded_instructions,
                discovery.decoded_instructions,
                options.max_instructions,
            )?;

            pending.extend(
                discovery
                    .callees
                    .iter()
                    .copied()
                    .filter(|address| !processed.contains(address)),
            );
            discoveries.push(discovery);
        }

        finalize(image, discoveries)
    }
}

#[derive(Clone, Debug)]
pub struct ParallelAnalyzer<D> {
    decoder: D,
}

impl<D> ParallelAnalyzer<D> {
    pub const fn new(decoder: D) -> Self {
        Self { decoder }
    }
}

impl<D: Decoder> Analyzer for ParallelAnalyzer<D> {
    fn analyze(
        &self,
        image: &BinaryImage,
        options: &AnalysisOptions,
    ) -> Result<AnalysisResult, AnalysisError> {
        let index = ExecutableAddressIndex::new(image);
        let mut pending = initial_function_seeds(image, options);
        let mut processed = BTreeSet::new();
        let mut all_discoveries = Vec::new();
        let mut decoded_instructions = 0_u64;

        while !pending.is_empty() {
            let wave: Vec<Address> = pending
                .iter()
                .copied()
                .filter(|entry| {
                    !processed.contains(entry) && is_executable_file_address(image, *entry)
                })
                .collect();
            pending.clear();

            if wave.is_empty() {
                break;
            }

            processed.extend(wave.iter().copied());

            let mut results: Vec<(Address, Result<FunctionDiscovery, AnalysisError>)> = wave
                .par_iter()
                .map_init(
                    || WorkerArena::new(&index),
                    |arena, entry| {
                        (
                            *entry,
                            discover_function(
                                &self.decoder,
                                image,
                                &index,
                                arena,
                                *entry,
                                options.max_instructions,
                            ),
                        )
                    },
                )
                .collect();

            results.sort_by_key(|(entry, _)| *entry);

            for (_, result) in results {
                let discovery = result?;
                charge_budget(
                    &mut decoded_instructions,
                    discovery.decoded_instructions,
                    options.max_instructions,
                )?;

                pending.extend(
                    discovery
                        .callees
                        .iter()
                        .copied()
                        .filter(|address| !processed.contains(address)),
                );
                all_discoveries.push(discovery);
            }
        }

        finalize(image, all_discoveries)
    }
}

fn discover_function<D: Decoder>(
    decoder: &D,
    image: &BinaryImage,
    index: &ExecutableAddressIndex,
    arena: &mut WorkerArena,
    entry: Address,
    max_instructions: Option<u64>,
) -> Result<FunctionDiscovery, AnalysisError> {
    arena.reset();

    let mut blocks = BTreeMap::new();
    let mut xrefs = BTreeSet::new();
    let mut callees = BTreeSet::new();
    let mut work = BTreeSet::from([entry]);
    let mut known_block_starts = BTreeSet::from([entry]);
    let mut decoded_instructions = 0_u64;
    let mut fidelity = Fidelity::Heuristic;

    while let Some(block_start) = work.pop_first() {
        if !is_executable_file_address(image, block_start)
            || !arena.visited.insert(index, block_start)
        {
            continue;
        }

        let mut current = block_start;
        let mut successors = BTreeSet::new();

        let end = loop {
            if current != block_start && known_block_starts.contains(&current) {
                successors.insert(current);
                break current;
            }

            if let Some(limit) = max_instructions {
                if decoded_instructions >= limit {
                    return Err(AnalysisError::BudgetExceeded);
                }
            }

            let Some(bytes) = image.bytes_at(current, 15) else {
                fidelity = Fidelity::Incomplete;
                break current;
            };

            let decoded = match decoder.decode(current, bytes) {
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
                        xrefs.insert((decoded.address, target, XrefKindKey::Call));
                        if is_executable_file_address(image, target) {
                            callees.insert(target);
                        }
                    }
                    current = next;
                }
                FlowKind::Branch => {
                    if let Some(target) = decoded.target {
                        xrefs.insert((decoded.address, target, XrefKindKey::Code));
                        enqueue_block(
                            image,
                            target,
                            &mut successors,
                            &mut known_block_starts,
                            &mut work,
                        );
                    }
                    break next;
                }
                FlowKind::ConditionalBranch => {
                    if let Some(target) = decoded.target {
                        xrefs.insert((decoded.address, target, XrefKindKey::Code));
                        enqueue_block(
                            image,
                            target,
                            &mut successors,
                            &mut known_block_starts,
                            &mut work,
                        );
                    }
                    enqueue_block(
                        image,
                        next,
                        &mut successors,
                        &mut known_block_starts,
                        &mut work,
                    );
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

    Ok(FunctionDiscovery {
        entry,
        blocks,
        xrefs,
        callees,
        fidelity,
        decoded_instructions,
    })
}

fn enqueue_block(
    image: &BinaryImage,
    address: Address,
    successors: &mut BTreeSet<Address>,
    known_block_starts: &mut BTreeSet<Address>,
    work: &mut BTreeSet<Address>,
) {
    if is_executable_file_address(image, address) {
        successors.insert(address);
        known_block_starts.insert(address);
        work.insert(address);
    }
}

fn finalize(
    image: &BinaryImage,
    discoveries: Vec<FunctionDiscovery>,
) -> Result<AnalysisResult, AnalysisError> {
    let mut function_entries = BTreeSet::new();
    let mut block_candidates: BTreeMap<Address, Vec<TempBlock>> = BTreeMap::new();
    let mut raw_xrefs = BTreeSet::new();
    let mut fidelity = Fidelity::Canonical;

    for discovery in discoveries {
        function_entries.insert(discovery.entry);
        fidelity = worse_fidelity(fidelity, discovery.fidelity);
        raw_xrefs.extend(discovery.xrefs);

        for (start, block) in discovery.blocks {
            block_candidates.entry(start).or_default().push(block);
        }
    }

    if !function_entries.is_empty() && fidelity == Fidelity::Canonical {
        fidelity = Fidelity::Heuristic;
    }

    let block_starts: BTreeSet<Address> = block_candidates.keys().copied().collect();
    let mut canonical_blocks = BTreeMap::new();

    for (start, candidates) in block_candidates {
        let mut block = candidates
            .into_iter()
            .min_by(|left, right| {
                left.end
                    .cmp(&right.end)
                    .then_with(|| left.successors.cmp(&right.successors))
            })
            .ok_or(AnalysisError::InternalInvariant)?;

        if let Some(split) = block_starts
            .range((Excluded(start), Excluded(block.end)))
            .next()
            .copied()
        {
            block.end = split;
            block.successors.clear();
            block.successors.insert(split);
        }

        canonical_blocks.insert(start, block);
    }

    let block_ids: BTreeMap<Address, BlockId> = canonical_blocks
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

    for (start, block) in &canonical_blocks {
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

    for (index, entry) in function_entries.into_iter().enumerate() {
        let id =
            FunctionId(u32::try_from(index).map_err(|_| AnalysisError::InternalInvariant)?);
        let reachable = reachable_blocks(entry, &canonical_blocks);
        let function_block_ids = reachable
            .iter()
            .filter_map(|address| block_ids.get(address).copied())
            .collect();

        cfg.functions.insert(
            id,
            Function {
                id,
                entry,
                blocks: function_block_ids,
                name: image
                    .preferred_function_name(entry)
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

fn reachable_blocks(
    entry: Address,
    blocks: &BTreeMap<Address, TempBlock>,
) -> BTreeSet<Address> {
    let mut reachable = BTreeSet::new();
    let mut pending = BTreeSet::from([entry]);

    while let Some(address) = pending.pop_first() {
        if !reachable.insert(address) {
            continue;
        }

        if let Some(block) = blocks.get(&address) {
            pending.extend(block.successors.iter().copied());
        }
    }

    reachable
}

fn charge_budget(
    total: &mut u64,
    amount: u64,
    limit: Option<u64>,
) -> Result<(), AnalysisError> {
    *total = total
        .checked_add(amount)
        .ok_or(AnalysisError::BudgetExceeded)?;

    if limit.is_some_and(|limit| *total > limit) {
        return Err(AnalysisError::BudgetExceeded);
    }

    Ok(())
}

fn initial_function_seeds(
    image: &BinaryImage,
    options: &AnalysisOptions,
) -> BTreeSet<Address> {
    if !options.entrypoints.is_empty() {
        return options.entrypoints.iter().copied().collect();
    }

    let mut seeds: BTreeSet<Address> = image
        .function_seeds
        .iter()
        .map(|seed| seed.address)
        .collect();

    if seeds.is_empty() {
        if let Some(entry) = image.entry_point {
            seeds.insert(entry);
        }
    }

    seeds
}

fn worse_fidelity(left: Fidelity, right: Fidelity) -> Fidelity {
    match (left, right) {
        (Fidelity::Incomplete, _) | (_, Fidelity::Incomplete) => Fidelity::Incomplete,
        (Fidelity::Heuristic, _) | (_, Fidelity::Heuristic) => Fidelity::Heuristic,
        _ => Fidelity::Canonical,
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

    fn assert_expected(result: &AnalysisResult) -> Result<(), AnalysisError> {
        assert_eq!(result.cfg.functions.len(), 2);
        assert_eq!(result.cfg.blocks.len(), 4);
        assert_eq!(result.xrefs.len(), 2);

        let entries: Vec<_> = result
            .cfg
            .functions
            .values()
            .map(|function| function.entry)
            .collect();
        assert_eq!(entries, vec![Address(0x1000), Address(0x1010)]);

        let helper = result
            .cfg
            .functions
            .values()
            .find(|function| function.entry == Address(0x1010))
            .ok_or(AnalysisError::InternalInvariant)?;
        assert_eq!(helper.name.as_deref(), Some("helper"));

        let starts: Vec<_> = result.cfg.blocks.values().map(|block| block.start).collect();
        assert_eq!(
            starts,
            vec![
                Address(0x1000),
                Address(0x1007),
                Address(0x100a),
                Address(0x1010)
            ]
        );

        assert_eq!(result.xrefs[0].from, Address(0x1000));
        assert_eq!(result.xrefs[0].to, Address(0x1010));
        assert_eq!(result.xrefs[0].kind, XrefKind::Call);
        assert_eq!(result.xrefs[1].from, Address(0x1005));
        assert_eq!(result.xrefs[1].to, Address(0x100a));
        assert_eq!(result.xrefs[1].kind, XrefKind::Code);

        Ok(())
    }

    #[test]
    fn sequential_and_parallel_results_match_exactly() -> Result<(), AnalysisError> {
        let image = test_image();
        let options = AnalysisOptions::default();
        let sequential = RecursiveAnalyzer::new(TestDecoder).analyze(&image, &options)?;
        let parallel = ParallelAnalyzer::new(TestDecoder).analyze(&image, &options)?;

        assert_eq!(sequential, parallel);
        assert_expected(&parallel)?;

        for _ in 0..16 {
            assert_eq!(
                ParallelAnalyzer::new(TestDecoder).analyze(&image, &options)?,
                sequential
            );
        }

        Ok(())
    }

    #[test]
    fn both_analyzers_enforce_instruction_budget() {
        let image = test_image();
        let options = AnalysisOptions {
            max_instructions: Some(1),
            ..AnalysisOptions::default()
        };

        assert_eq!(
            RecursiveAnalyzer::new(TestDecoder).analyze(&image, &options),
            Err(AnalysisError::BudgetExceeded)
        );
        assert_eq!(
            ParallelAnalyzer::new(TestDecoder).analyze(&image, &options),
            Err(AnalysisError::BudgetExceeded)
        );
    }
}
