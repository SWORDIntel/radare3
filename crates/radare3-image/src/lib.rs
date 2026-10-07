#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use radare3_types::{Address, Architecture, BinaryFormat};

#[derive(Clone)]
pub enum BinaryData {
    Owned(Arc<[u8]>),
    Mapped(Arc<memmap2::Mmap>),
}

impl BinaryData {
    pub fn owned(bytes: Arc<[u8]>) -> Self {
        Self::Owned(bytes)
    }

    pub fn mapped(bytes: Arc<memmap2::Mmap>) -> Self {
        Self::Mapped(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped(bytes) => bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self, Self::Mapped(_))
    }
}

impl fmt::Debug for BinaryData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryData")
            .field("len", &self.len())
            .field("mapped", &self.is_mapped())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FunctionSeedKind {
    Entry,
    Symbol,
    Export,
    ExceptionTable,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FunctionSeed {
    pub address: Address,
    pub kind: FunctionSeedKind,
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymbolKind {
    Function,
    Object,
    Export,
    Other,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Symbol {
    pub address: Address,
    pub size: u64,
    pub kind: SymbolKind,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ImportKind {
    Function,
    Object,
    Other,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Import {
    pub slot: Option<Address>,
    pub library: Option<String>,
    pub name: String,
    pub ordinal: Option<u16>,
    pub kind: ImportKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportIndex {
    by_slot: Vec<(Address, usize)>,
}

impl ImportIndex {
    pub fn build(imports: &[Import]) -> Self {
        let mut by_slot = imports
            .iter()
            .enumerate()
            .filter_map(|(position, import)| import.slot.map(|slot| (slot, position)))
            .collect::<Vec<_>>();

        by_slot.sort_unstable_by_key(|(slot, position)| (*slot, *position));
        by_slot.dedup_by_key(|(slot, _)| *slot);

        Self { by_slot }
    }

    pub fn position(&self, slot: Address) -> Option<usize> {
        self.by_slot
            .binary_search_by_key(&slot, |(address, _)| *address)
            .ok()
            .and_then(|index| self.by_slot.get(index))
            .map(|(_, position)| *position)
    }

    pub fn import<'a>(&self, imports: &'a [Import], slot: Address) -> Option<&'a Import> {
        self.position(slot)
            .and_then(|position| imports.get(position))
    }

    pub fn len(&self) -> usize {
        self.by_slot.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_slot.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment {
    pub name: String,
    pub address: Address,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub permissions: Permissions,
}

impl Segment {
    pub fn contains_file_address(&self, address: Address) -> bool {
        let Some(end) = self.address.0.checked_add(self.file_size) else {
            return false;
        };
        address.0 >= self.address.0 && address.0 < end
    }

    pub fn contains_file_offset(&self, file_offset: u64) -> bool {
        let Some(end) = self.file_offset.checked_add(self.file_size) else {
            return false;
        };
        file_offset >= self.file_offset && file_offset < end
    }
}

#[derive(Clone, Debug)]
pub struct BinaryImage {
    bytes: BinaryData,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub base_address: Address,
    pub entry_point: Option<Address>,
    pub segments: Vec<Segment>,
    pub function_seeds: Vec<FunctionSeed>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
}

impl BinaryImage {
    pub fn new(
        bytes: Arc<[u8]>,
        format: BinaryFormat,
        architecture: Architecture,
        base_address: Address,
        entry_point: Option<Address>,
        segments: Vec<Segment>,
    ) -> Self {
        Self::from_data(
            BinaryData::owned(bytes),
            format,
            architecture,
            base_address,
            entry_point,
            segments,
        )
    }

    pub fn from_data(
        bytes: BinaryData,
        format: BinaryFormat,
        architecture: Architecture,
        base_address: Address,
        entry_point: Option<Address>,
        segments: Vec<Segment>,
    ) -> Self {
        let function_seeds = entry_point
            .map(|address| {
                vec![FunctionSeed {
                    address,
                    kind: FunctionSeedKind::Entry,
                    name: None,
                }]
            })
            .unwrap_or_default();

        Self {
            bytes,
            format,
            architecture,
            base_address,
            entry_point,
            segments,
            function_seeds,
            symbols: Vec::new(),
            imports: Vec::new(),
        }
    }

    pub fn with_function_seeds(mut self, mut function_seeds: Vec<FunctionSeed>) -> Self {
        self.function_seeds.append(&mut function_seeds);
        self.function_seeds.sort();
        self.function_seeds.dedup();
        self
    }

    pub fn with_symbols(mut self, mut symbols: Vec<Symbol>) -> Self {
        self.symbols.append(&mut symbols);
        self.symbols.sort();
        self.symbols.dedup();
        self
    }

    pub fn with_imports(mut self, mut imports: Vec<Import>) -> Self {
        self.imports.append(&mut imports);
        self.imports.sort();
        self.imports.dedup();
        self
    }

    pub fn import_at_slot(&self, address: Address) -> Option<&Import> {
        self.imports
            .iter()
            .find(|import| import.slot == Some(address))
    }

    pub fn preferred_function_name(&self, address: Address) -> Option<&str> {
        self.function_seeds
            .iter()
            .filter(|seed| seed.address == address)
            .filter_map(|seed| seed.name.as_deref())
            .find(|name| !name.is_empty())
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn is_mapped(&self) -> bool {
        self.bytes.is_mapped()
    }

    fn file_backed_segment_and_offset(&self, address: Address) -> Option<(&Segment, usize)> {
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.contains_file_address(address))?;
        let delta = address.0.checked_sub(segment.address.0)?;
        let offset = segment.file_offset.checked_add(delta)?;
        let offset = usize::try_from(offset).ok()?;
        Some((segment, offset))
    }

    pub fn address_to_file_offset(&self, address: Address) -> Option<usize> {
        self.file_backed_segment_and_offset(address)
            .map(|(_, offset)| offset)
    }

    pub fn file_offset_to_address(&self, file_offset: u64) -> Option<Address> {
        self.segments.iter().find_map(|segment| {
            if !segment.contains_file_offset(file_offset) {
                return None;
            }

            let delta = file_offset.checked_sub(segment.file_offset)?;
            segment.address.0.checked_add(delta).map(Address)
        })
    }

    pub fn bytes_at(&self, address: Address, max_len: usize) -> Option<&[u8]> {
        let (segment, offset) = self.file_backed_segment_and_offset(address)?;
        let delta = address.0.checked_sub(segment.address.0)?;
        let remaining = segment.file_size.checked_sub(delta)?;
        let remaining = usize::try_from(remaining).ok()?;
        let len = max_len.min(remaining);
        let end = offset.checked_add(len)?;

        self.bytes().get(offset..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_virtual_addresses_and_file_offsets() {
        let image = BinaryImage::new(
            Arc::from([0_u8; 32]),
            BinaryFormat::Raw,
            Architecture::Unknown,
            Address(0x1000),
            None,
            vec![Segment {
                name: "test".to_string(),
                address: Address(0x1000),
                file_offset: 4,
                file_size: 8,
                memory_size: 16,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
        );

        assert_eq!(image.address_to_file_offset(Address(0x1003)), Some(7));
        assert_eq!(image.file_offset_to_address(7), Some(Address(0x1003)));
        assert_eq!(image.address_to_file_offset(Address(0x1008)), None);
        assert_eq!(image.file_offset_to_address(12), None);
        assert_eq!(
            image.bytes_at(Address(0x1006), 15).map(<[u8]>::len),
            Some(2)
        );
        assert!(!image.is_mapped());
    }

    #[test]
    fn resolves_import_by_slot() {
        let image = BinaryImage::new(
            Arc::from([0xc3_u8]),
            BinaryFormat::Raw,
            Architecture::X86_64,
            Address(0x1000),
            None,
            vec![],
        )
        .with_imports(vec![Import {
            slot: Some(Address(0x2000)),
            library: Some("libc.so.6".to_string()),
            name: "puts".to_string(),
            ordinal: None,
            kind: ImportKind::Function,
        }]);

        assert_eq!(
            image
                .import_at_slot(Address(0x2000))
                .map(|import| import.name.as_str()),
            Some("puts")
        );
        assert_eq!(image.import_at_slot(Address(0x2008)), None);
    }

    #[test]
    fn import_index_resolves_first_canonical_slot_entry() {
        let imports = vec![
            Import {
                slot: Some(Address(0x2000)),
                library: Some("a.dll".to_string()),
                name: "first".to_string(),
                ordinal: None,
                kind: ImportKind::Function,
            },
            Import {
                slot: Some(Address(0x2000)),
                library: Some("b.dll".to_string()),
                name: "second".to_string(),
                ordinal: None,
                kind: ImportKind::Function,
            },
            Import {
                slot: Some(Address(0x3000)),
                library: None,
                name: "third".to_string(),
                ordinal: None,
                kind: ImportKind::Object,
            },
            Import {
                slot: None,
                library: None,
                name: "noslot".to_string(),
                ordinal: None,
                kind: ImportKind::Other,
            },
        ];
        let index = ImportIndex::build(&imports);

        assert_eq!(index.len(), 2);
        assert!(!index.is_empty());
        assert_eq!(index.position(Address(0x2000)), Some(0));
        assert_eq!(
            index
                .import(&imports, Address(0x2000))
                .map(|import| import.name.as_str()),
            Some("first")
        );
        assert_eq!(
            index
                .import(&imports, Address(0x3000))
                .map(|import| import.name.as_str()),
            Some("third")
        );
        assert_eq!(index.import(&imports, Address(0x4000)), None);
    }

    #[test]
    fn empty_import_index_is_empty() {
        let index = ImportIndex::build(&[]);

        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert_eq!(index.position(Address(0x2000)), None);
    }

    #[test]
    fn canonicalizes_imports() {
        let image = BinaryImage::new(
            Arc::from([0xc3_u8]),
            BinaryFormat::Raw,
            Architecture::X86_64,
            Address(0x1000),
            None,
            vec![],
        )
        .with_imports(vec![
            Import {
                slot: Some(Address(0x2000)),
                library: Some("libc.so.6".to_string()),
                name: "puts".to_string(),
                ordinal: None,
                kind: ImportKind::Function,
            },
            Import {
                slot: Some(Address(0x2000)),
                library: Some("libc.so.6".to_string()),
                name: "puts".to_string(),
                ordinal: None,
                kind: ImportKind::Function,
            },
        ]);

        assert_eq!(image.imports.len(), 1);
        assert_eq!(image.imports[0].name, "puts");
    }

    #[test]
    fn canonicalizes_symbols() {
        let image = BinaryImage::new(
            Arc::from([0xc3_u8]),
            BinaryFormat::Raw,
            Architecture::X86_64,
            Address(0x1000),
            None,
            vec![],
        )
        .with_symbols(vec![
            Symbol {
                address: Address(0x1000),
                size: 1,
                kind: SymbolKind::Function,
                name: "main".to_string(),
            },
            Symbol {
                address: Address(0x1000),
                size: 1,
                kind: SymbolKind::Function,
                name: "main".to_string(),
            },
        ]);

        assert_eq!(image.symbols.len(), 1);
        assert_eq!(image.symbols[0].name, "main");
    }

    #[test]
    fn canonicalizes_and_names_function_seeds() {
        let image = BinaryImage::new(
            Arc::from([0xc3_u8]),
            BinaryFormat::Raw,
            Architecture::X86_64,
            Address(0x1000),
            Some(Address(0x1000)),
            vec![],
        )
        .with_function_seeds(vec![
            FunctionSeed {
                address: Address(0x1000),
                kind: FunctionSeedKind::Symbol,
                name: Some("main".to_string()),
            },
            FunctionSeed {
                address: Address(0x1000),
                kind: FunctionSeedKind::Symbol,
                name: Some("main".to_string()),
            },
        ]);

        assert_eq!(image.function_seeds.len(), 2);
        assert_eq!(image.preferred_function_name(Address(0x1000)), Some("main"));
    }
}
