#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use radare3_analysis::{AnalysisOptions, AnalysisResult};
use radare3_cfg::{BasicBlock, ControlFlowGraph, Function};
use radare3_search::{ExtractedString, StringEncoding};
use radare3_types::{Address, BlockId, Fidelity, FunctionId, XrefId};
use radare3_xref::{Xref, XrefKind};

const CACHE_KEY_DOMAIN: &[u8] = b"radare3-cache-key-v1";
const CACHE_FILE_MAGIC: &[u8; 8] = b"R3CACHE\0";
const CACHE_FILE_VERSION: u32 = 1;
const CACHE_FILE_HEADER_BYTES: u64 = 8 + 4 + 32 + 8 + 32;
const ANALYSIS_PAYLOAD_MAGIC: &[u8; 8] = b"R3ANLYS\0";
const ANALYSIS_PAYLOAD_VERSION: u32 = 1;
const MAX_COLLECTION_ITEMS: u32 = 10_000_000;
const MAX_STRING_BYTES: u32 = 16 * 1024 * 1024;

pub const CURRENT_ANALYSIS_SCHEMA: u32 = 1;
pub const DEFAULT_MAX_CACHE_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheKey(pub [u8; 32]);

impl CacheKey {
    pub fn derive(identity: &CacheIdentity<'_>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hash_component(&mut hasher, CACHE_KEY_DOMAIN);
        hash_component(&mut hasher, identity.binary);
        hash_component(&mut hasher, identity.loader_version.as_bytes());
        hash_component(&mut hasher, identity.decoder_version.as_bytes());
        hash_component(&mut hasher, &identity.analysis_schema.to_le_bytes());
        hash_component(&mut hasher, identity.options_fingerprint);

        Self(*hasher.finalize().as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CacheIdentity<'a> {
    pub binary: &'a [u8],
    pub loader_version: &'a str,
    pub decoder_version: &'a str,
    pub analysis_schema: u32,
    pub options_fingerprint: &'a [u8],
}

impl<'a> CacheIdentity<'a> {
    pub const fn new(
        binary: &'a [u8],
        loader_version: &'a str,
        decoder_version: &'a str,
        options_fingerprint: &'a [u8],
    ) -> Self {
        Self {
            binary,
            loader_version,
            decoder_version,
            analysis_schema: CURRENT_ANALYSIS_SCHEMA,
            options_fingerprint,
        }
    }

    pub const fn with_schema(mut self, analysis_schema: u32) -> Self {
        self.analysis_schema = analysis_schema;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheError {
    Corrupt,
    IncompatibleVersion,
    Io,
    TooLarge,
}

impl From<io::Error> for CacheError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

pub trait AnalysisCache: Send + Sync {
    fn contains(&self, key: CacheKey) -> Result<bool, CacheError>;
    fn get(&self, key: CacheKey) -> Result<Option<Vec<u8>>, CacheError>;
    fn put(&self, key: CacheKey, payload: &[u8]) -> Result<(), CacheError>;
    fn remove(&self, key: CacheKey) -> Result<(), CacheError>;
}

#[derive(Clone, Debug)]
pub struct FileCache {
    root: PathBuf,
    max_payload_bytes: u64,
}

impl FileCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_payload_bytes: DEFAULT_MAX_CACHE_PAYLOAD_BYTES,
        }
    }

    pub fn with_max_payload_bytes(mut self, max_payload_bytes: u64) -> Self {
        self.max_payload_bytes = max_payload_bytes;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, key: CacheKey) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(&hex[..2]).join(format!("{hex}.r3c"))
    }

    fn temp_path_for(&self, key: CacheKey) -> PathBuf {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let final_path = self.path_for(key);
        let file_name = format!(".{}.{}.{}.tmp", key, std::process::id(), sequence);
        final_path
            .parent()
            .map(|parent| parent.join(&file_name))
            .unwrap_or_else(|| self.root.join(&file_name))
    }
}

impl AnalysisCache for FileCache {
    fn contains(&self, key: CacheKey) -> Result<bool, CacheError> {
        Ok(self.path_for(key).try_exists()?)
    }

    fn get(&self, key: CacheKey) -> Result<Option<Vec<u8>>, CacheError> {
        let path = self.path_for(key);
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let file_len = file.metadata()?.len();

        let mut magic = [0_u8; 8];
        read_exact_cache(&mut file, &mut magic)?;
        if &magic != CACHE_FILE_MAGIC {
            return Err(CacheError::Corrupt);
        }

        let version = read_u32_io(&mut file)?;
        if version != CACHE_FILE_VERSION {
            return Err(CacheError::IncompatibleVersion);
        }

        let mut stored_key = [0_u8; 32];
        read_exact_cache(&mut file, &mut stored_key)?;
        if stored_key != key.0 {
            return Err(CacheError::Corrupt);
        }

        let payload_len = read_u64_io(&mut file)?;
        if payload_len > self.max_payload_bytes {
            return Err(CacheError::TooLarge);
        }

        let expected_file_len = CACHE_FILE_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(CacheError::TooLarge)?;
        if file_len != expected_file_len {
            return Err(CacheError::Corrupt);
        }

        let payload_len = usize::try_from(payload_len).map_err(|_| CacheError::TooLarge)?;
        let mut expected_hash = [0_u8; 32];
        read_exact_cache(&mut file, &mut expected_hash)?;

        let mut payload = vec![0_u8; payload_len];
        read_exact_cache(&mut file, &mut payload)?;

        if blake3::hash(&payload).as_bytes() != &expected_hash {
            return Err(CacheError::Corrupt);
        }

        Ok(Some(payload))
    }

    fn put(&self, key: CacheKey, payload: &[u8]) -> Result<(), CacheError> {
        let payload_len = u64::try_from(payload.len()).map_err(|_| CacheError::TooLarge)?;
        if payload_len > self.max_payload_bytes {
            return Err(CacheError::TooLarge);
        }

        let final_path = self.path_for(key);
        if final_path.try_exists()? {
            return Ok(());
        }

        let parent = final_path.parent().ok_or(CacheError::Io)?;
        fs::create_dir_all(parent)?;

        let temp_path = self.temp_path_for(key);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;

        let write_result = (|| -> Result<(), CacheError> {
            file.write_all(CACHE_FILE_MAGIC)?;
            file.write_all(&CACHE_FILE_VERSION.to_le_bytes())?;
            file.write_all(key.as_bytes())?;
            file.write_all(&payload_len.to_le_bytes())?;
            file.write_all(blake3::hash(payload).as_bytes())?;
            file.write_all(payload)?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        match fs::rename(&temp_path, &final_path) {
            Ok(()) => Ok(()),
            Err(_) if final_path.try_exists()? => {
                let _ = fs::remove_file(&temp_path);
                Ok(())
            }
            Err(error) => {
                let _ = fs::remove_file(&temp_path);
                Err(error.into())
            }
        }
    }

    fn remove(&self, key: CacheKey) -> Result<(), CacheError> {
        match fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisSnapshot {
    pub analysis: AnalysisResult,
    pub strings: Vec<ExtractedString>,
}

impl AnalysisSnapshot {
    pub fn new(analysis: AnalysisResult, strings: Vec<ExtractedString>) -> Self {
        Self { analysis, strings }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CacheError> {
        let mut out = Vec::new();
        out.extend_from_slice(ANALYSIS_PAYLOAD_MAGIC);
        push_u32(&mut out, ANALYSIS_PAYLOAD_VERSION);
        out.push(encode_fidelity(self.analysis.fidelity));

        push_count(&mut out, self.analysis.cfg.functions.len())?;
        for function in self.analysis.cfg.functions.values() {
            push_u32(&mut out, function.id.0);
            push_u64(&mut out, function.entry.0);
            push_count(&mut out, function.blocks.len())?;
            for block in &function.blocks {
                push_u32(&mut out, block.0);
            }
            push_optional_string(&mut out, function.name.as_deref())?;
        }

        push_count(&mut out, self.analysis.cfg.blocks.len())?;
        for block in self.analysis.cfg.blocks.values() {
            push_u32(&mut out, block.id.0);
            push_u64(&mut out, block.start.0);
            push_u64(&mut out, block.end.0);
            push_count(&mut out, block.successors.len())?;
            for successor in &block.successors {
                push_u32(&mut out, successor.0);
            }
        }

        push_count(&mut out, self.analysis.xrefs.len())?;
        for xref in &self.analysis.xrefs {
            push_u32(&mut out, xref.id.0);
            push_u64(&mut out, xref.from.0);
            push_u64(&mut out, xref.to.0);
            out.push(encode_xref_kind(xref.kind));
        }

        push_count(&mut out, self.strings.len())?;
        for string in &self.strings {
            push_u64(&mut out, string.address.0);
            out.push(encode_string_encoding(string.encoding));
            push_string(&mut out, &string.value)?;
        }

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CacheError> {
        let payload_len = u64::try_from(bytes.len()).map_err(|_| CacheError::TooLarge)?;
        if payload_len > DEFAULT_MAX_CACHE_PAYLOAD_BYTES {
            return Err(CacheError::TooLarge);
        }

        let mut reader = SliceReader::new(bytes);
        if reader.take(ANALYSIS_PAYLOAD_MAGIC.len())? != ANALYSIS_PAYLOAD_MAGIC {
            return Err(CacheError::Corrupt);
        }

        if reader.read_u32()? != ANALYSIS_PAYLOAD_VERSION {
            return Err(CacheError::IncompatibleVersion);
        }

        let fidelity = decode_fidelity(reader.read_u8()?)?;

        let function_count = reader.read_count_with_minimum(17)?;
        let mut functions = BTreeMap::new();
        for _ in 0..function_count {
            let id = FunctionId(reader.read_u32()?);
            let entry = Address(reader.read_u64()?);
            let block_count = reader.read_count_with_minimum(4)?;
            let mut blocks = Vec::with_capacity(block_count);
            for _ in 0..block_count {
                blocks.push(BlockId(reader.read_u32()?));
            }
            let name = reader.read_optional_string()?;

            if functions
                .insert(
                    id,
                    Function {
                        id,
                        entry,
                        blocks,
                        name,
                    },
                )
                .is_some()
            {
                return Err(CacheError::Corrupt);
            }
        }

        let basic_block_count = reader.read_count_with_minimum(24)?;
        let mut blocks = BTreeMap::new();
        for _ in 0..basic_block_count {
            let id = BlockId(reader.read_u32()?);
            let start = Address(reader.read_u64()?);
            let end = Address(reader.read_u64()?);
            let successor_count = reader.read_count_with_minimum(4)?;
            let mut successors = Vec::with_capacity(successor_count);
            for _ in 0..successor_count {
                successors.push(BlockId(reader.read_u32()?));
            }

            if blocks
                .insert(
                    id,
                    BasicBlock {
                        id,
                        start,
                        end,
                        successors,
                    },
                )
                .is_some()
            {
                return Err(CacheError::Corrupt);
            }
        }

        validate_cfg_references(&functions, &blocks)?;

        let xref_count = reader.read_count_with_minimum(21)?;
        let mut xrefs = Vec::with_capacity(xref_count);
        let mut xref_ids = BTreeSet::new();
        for _ in 0..xref_count {
            let id = XrefId(reader.read_u32()?);
            if !xref_ids.insert(id) {
                return Err(CacheError::Corrupt);
            }
            xrefs.push(Xref {
                id,
                from: Address(reader.read_u64()?),
                to: Address(reader.read_u64()?),
                kind: decode_xref_kind(reader.read_u8()?)?,
            });
        }

        let string_count = reader.read_count_with_minimum(13)?;
        let mut strings = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            strings.push(ExtractedString {
                address: Address(reader.read_u64()?),
                encoding: decode_string_encoding(reader.read_u8()?)?,
                value: reader.read_string()?,
            });
        }

        if !reader.is_finished() {
            return Err(CacheError::Corrupt);
        }

        Ok(Self {
            analysis: AnalysisResult {
                cfg: ControlFlowGraph { functions, blocks },
                xrefs,
                fidelity,
            },
            strings,
        })
    }
}

pub fn analysis_options_fingerprint(
    options: &AnalysisOptions,
    string_min_chars: usize,
) -> Result<Vec<u8>, CacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(b"r3-analysis-options-v1");
    out.push(u8::from(options.deterministic));

    match options.max_instructions {
        Some(limit) => {
            out.push(1);
            push_u64(&mut out, limit);
        }
        None => out.push(0),
    }

    let mut entrypoints = options.entrypoints.clone();
    entrypoints.sort();
    entrypoints.dedup();
    push_count(&mut out, entrypoints.len())?;
    for entry in entrypoints {
        push_u64(&mut out, entry.0);
    }

    let min_chars = u64::try_from(string_min_chars).map_err(|_| CacheError::TooLarge)?;
    push_u64(&mut out, min_chars);
    Ok(out)
}

fn validate_cfg_references(
    functions: &BTreeMap<FunctionId, Function>,
    blocks: &BTreeMap<BlockId, BasicBlock>,
) -> Result<(), CacheError> {
    for function in functions.values() {
        if function.blocks.iter().any(|id| !blocks.contains_key(id)) {
            return Err(CacheError::Corrupt);
        }
    }

    for block in blocks.values() {
        if block.successors.iter().any(|id| !blocks.contains_key(id)) {
            return Err(CacheError::Corrupt);
        }
        if block.end < block.start {
            return Err(CacheError::Corrupt);
        }
    }

    Ok(())
}

fn push_count(out: &mut Vec<u8>, count: usize) -> Result<(), CacheError> {
    let count = u32::try_from(count).map_err(|_| CacheError::TooLarge)?;
    if count > MAX_COLLECTION_ITEMS {
        return Err(CacheError::TooLarge);
    }
    push_u32(out, count);
    Ok(())
}

fn push_optional_string(out: &mut Vec<u8>, value: Option<&str>) -> Result<(), CacheError> {
    match value {
        Some(value) => {
            out.push(1);
            push_string(out, value)
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), CacheError> {
    let len = u32::try_from(value.len()).map_err(|_| CacheError::TooLarge)?;
    if len > MAX_STRING_BYTES {
        return Err(CacheError::TooLarge);
    }
    push_u32(out, len);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

const fn encode_fidelity(value: Fidelity) -> u8 {
    match value {
        Fidelity::Canonical => 0,
        Fidelity::Heuristic => 1,
        Fidelity::Incomplete => 2,
    }
}

fn decode_fidelity(value: u8) -> Result<Fidelity, CacheError> {
    match value {
        0 => Ok(Fidelity::Canonical),
        1 => Ok(Fidelity::Heuristic),
        2 => Ok(Fidelity::Incomplete),
        _ => Err(CacheError::Corrupt),
    }
}

const fn encode_xref_kind(value: XrefKind) -> u8 {
    match value {
        XrefKind::Call => 0,
        XrefKind::Code => 1,
        XrefKind::Data => 2,
    }
}

fn decode_xref_kind(value: u8) -> Result<XrefKind, CacheError> {
    match value {
        0 => Ok(XrefKind::Call),
        1 => Ok(XrefKind::Code),
        2 => Ok(XrefKind::Data),
        _ => Err(CacheError::Corrupt),
    }
}

const fn encode_string_encoding(value: StringEncoding) -> u8 {
    match value {
        StringEncoding::Ascii => 0,
        StringEncoding::Utf16Le => 1,
    }
}

fn decode_string_encoding(value: u8) -> Result<StringEncoding, CacheError> {
    match value {
        0 => Ok(StringEncoding::Ascii),
        1 => Ok(StringEncoding::Utf16Le),
        _ => Err(CacheError::Corrupt),
    }
}

struct SliceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CacheError> {
        let end = self.offset.checked_add(len).ok_or(CacheError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CacheError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, CacheError> {
        Ok(*self.take(1)?.first().ok_or(CacheError::Corrupt)?)
    }

    fn read_u32(&mut self) -> Result<u32, CacheError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| CacheError::Corrupt)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, CacheError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| CacheError::Corrupt)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_count(&mut self) -> Result<usize, CacheError> {
        let count = self.read_u32()?;
        if count > MAX_COLLECTION_ITEMS {
            return Err(CacheError::TooLarge);
        }
        usize::try_from(count).map_err(|_| CacheError::TooLarge)
    }

    fn read_count_with_minimum(&mut self, minimum_bytes_per_item: usize) -> Result<usize, CacheError> {
        let count = self.read_count()?;
        if minimum_bytes_per_item != 0
            && count > self.remaining() / minimum_bytes_per_item
        {
            return Err(CacheError::Corrupt);
        }
        Ok(count)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_optional_string(&mut self) -> Result<Option<String>, CacheError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => self.read_string().map(Some),
            _ => Err(CacheError::Corrupt),
        }
    }

    fn read_string(&mut self) -> Result<String, CacheError> {
        let len = self.read_u32()?;
        if len > MAX_STRING_BYTES {
            return Err(CacheError::TooLarge);
        }
        let len = usize::try_from(len).map_err(|_| CacheError::TooLarge)?;
        let value = std::str::from_utf8(self.take(len)?).map_err(|_| CacheError::Corrupt)?;
        Ok(value.to_owned())
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn hash_component(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn read_exact_cache(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), CacheError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(CacheError::Corrupt),
        Err(_) => Err(CacheError::Io),
    }
}

fn read_u32_io(reader: &mut impl Read) -> Result<u32, CacheError> {
    let mut bytes = [0_u8; 4];
    read_exact_cache(reader, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_io(reader: &mut impl Read) -> Result<u64, CacheError> {
    let mut bytes = [0_u8; 8];
    read_exact_cache(reader, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity<'a>() -> CacheIdentity<'a> {
        CacheIdentity::new(
            b"binary bytes",
            "goblin-0.10.7/radare3-loader-v1",
            "iced-x86-1.21.0/radare3-x86-v1",
            b"deterministic=true;entrypoints=[];max_instructions=none",
        )
    }

    fn test_root(name: &str) -> PathBuf {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "radare3-cache-test-{}-{}-{sequence}",
            std::process::id(),
            name
        ))
    }

    fn snapshot() -> AnalysisSnapshot {
        let block = BasicBlock {
            id: BlockId(0),
            start: Address(0x1000),
            end: Address(0x1001),
            successors: Vec::new(),
        };
        let function = Function {
            id: FunctionId(0),
            entry: Address(0x1000),
            blocks: vec![BlockId(0)],
            name: Some("entry".to_string()),
        };

        AnalysisSnapshot::new(
            AnalysisResult {
                cfg: ControlFlowGraph {
                    functions: BTreeMap::from([(FunctionId(0), function)]),
                    blocks: BTreeMap::from([(BlockId(0), block)]),
                },
                xrefs: vec![Xref {
                    id: XrefId(0),
                    from: Address(0x1000),
                    to: Address(0x2000),
                    kind: XrefKind::Call,
                }],
                fidelity: Fidelity::Heuristic,
            },
            vec![ExtractedString {
                address: Address(0x3000),
                encoding: StringEncoding::Ascii,
                value: "radare3".to_string(),
            }],
        )
    }

    #[test]
    fn cache_key_is_deterministic() {
        let first = CacheKey::derive(&identity());
        let second = CacheKey::derive(&identity());

        assert_eq!(first, second);
        assert_eq!(first.to_string().len(), 64);
        assert_eq!(first.to_hex(), first.to_string());
    }

    #[test]
    fn every_identity_component_changes_the_key() {
        let base = CacheKey::derive(&identity());

        let variants = [
            CacheIdentity::new(
                b"binary bytes changed",
                identity().loader_version,
                identity().decoder_version,
                identity().options_fingerprint,
            ),
            CacheIdentity::new(
                identity().binary,
                "loader-v2",
                identity().decoder_version,
                identity().options_fingerprint,
            ),
            CacheIdentity::new(
                identity().binary,
                identity().loader_version,
                "decoder-v2",
                identity().options_fingerprint,
            ),
            CacheIdentity::new(
                identity().binary,
                identity().loader_version,
                identity().decoder_version,
                b"different-options",
            ),
            identity().with_schema(CURRENT_ANALYSIS_SCHEMA + 1),
        ];

        for variant in variants {
            assert_ne!(CacheKey::derive(&variant), base);
        }
    }

    #[test]
    fn snapshot_round_trips_deterministically() -> Result<(), CacheError> {
        let snapshot = snapshot();
        let first = snapshot.encode()?;
        let second = snapshot.encode()?;
        assert_eq!(first, second);
        assert_eq!(AnalysisSnapshot::decode(&first)?, snapshot);
        Ok(())
    }

    #[test]
    fn snapshot_rejects_trailing_and_corrupt_bytes() -> Result<(), CacheError> {
        let mut encoded = snapshot().encode()?;
        encoded.push(0);
        assert_eq!(AnalysisSnapshot::decode(&encoded), Err(CacheError::Corrupt));

        let mut encoded = snapshot().encode()?;
        encoded[0] ^= 0xff;
        assert_eq!(AnalysisSnapshot::decode(&encoded), Err(CacheError::Corrupt));
        Ok(())
    }

    #[test]
    fn snapshot_rejects_every_truncated_prefix() -> Result<(), CacheError> {
        let encoded = snapshot().encode()?;

        for end in 0..encoded.len() {
            assert_eq!(
                AnalysisSnapshot::decode(&encoded[..end]),
                Err(CacheError::Corrupt),
                "truncated at byte {end}"
            );
        }

        Ok(())
    }

    #[test]
    fn snapshot_rejects_impossible_large_count_before_allocation() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(ANALYSIS_PAYLOAD_MAGIC);
        push_u32(&mut encoded, ANALYSIS_PAYLOAD_VERSION);
        encoded.push(encode_fidelity(Fidelity::Heuristic));
        push_u32(&mut encoded, MAX_COLLECTION_ITEMS);

        assert_eq!(AnalysisSnapshot::decode(&encoded), Err(CacheError::Corrupt));
    }

    #[test]
    fn options_fingerprint_is_order_independent_for_entrypoints() -> Result<(), CacheError> {
        let left = AnalysisOptions {
            entrypoints: vec![Address(2), Address(1), Address(2)],
            max_instructions: Some(100),
            deterministic: true,
        };
        let right = AnalysisOptions {
            entrypoints: vec![Address(1), Address(2)],
            max_instructions: Some(100),
            deterministic: true,
        };

        assert_eq!(
            analysis_options_fingerprint(&left, 4)?,
            analysis_options_fingerprint(&right, 4)?
        );
        Ok(())
    }

    #[test]
    fn file_cache_round_trips_and_detects_corruption() -> Result<(), CacheError> {
        let root = test_root("roundtrip");
        let cache = FileCache::new(&root);
        let key = CacheKey::derive(&identity());
        let payload = b"opaque deterministic analysis payload";

        assert!(!cache.contains(key)?);
        assert_eq!(cache.get(key)?, None);

        cache.put(key, payload)?;
        assert!(cache.contains(key)?);
        assert_eq!(cache.get(key)?, Some(payload.to_vec()));

        let path = cache.path_for(key);
        fs::write(&path, b"NOTCACHE-corrupt")?;
        assert_eq!(cache.get(key), Err(CacheError::Corrupt));
        cache.remove(key)?;
        assert!(!cache.contains(key)?);

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn file_cache_treats_truncated_entries_as_corrupt() -> Result<(), CacheError> {
        let root = test_root("truncated");
        let cache = FileCache::new(&root);
        let key = CacheKey::derive(&identity());
        cache.put(key, b"cache payload")?;

        let path = cache.path_for(key);
        let valid = fs::read(&path)?;
        let cuts = [0, 1, 7, 8, 11, 12, 43, 51, valid.len() - 1];

        for cut in cuts {
            fs::write(&path, &valid[..cut])?;
            assert_eq!(cache.get(key), Err(CacheError::Corrupt), "cut={cut}");
        }

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn file_cache_rejects_forged_large_payload_before_allocation() -> Result<(), CacheError> {
        let root = test_root("forged-length");
        let cache = FileCache::new(&root);
        let key = CacheKey::derive(&identity());
        cache.put(key, b"x")?;

        let path = cache.path_for(key);
        let mut bytes = fs::read(&path)?;
        let forged = DEFAULT_MAX_CACHE_PAYLOAD_BYTES;
        bytes[44..52].copy_from_slice(&forged.to_le_bytes());
        fs::write(&path, bytes)?;

        assert_eq!(cache.get(key), Err(CacheError::Corrupt));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn file_cache_enforces_payload_limit() {
        let root = test_root("limit");
        let cache = FileCache::new(&root).with_max_payload_bytes(4);
        let key = CacheKey::derive(&identity());

        assert_eq!(cache.put(key, b"12345"), Err(CacheError::TooLarge));

        let _ = fs::remove_dir_all(root);
    }
}
