#![forbid(unsafe_code)]

use std::sync::Arc;

use radare3_types::{Address, Architecture, BinaryFormat};

use crate::{GoblinLoader, LoadError, Loader};

pub const DEFAULT_MAX_FUZZ_INPUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_OUTPUT_SEGMENTS: usize = 65_536;
pub const DEFAULT_MAX_OUTPUT_SEEDS: usize = 1_000_000;
pub const DEFAULT_MAX_OUTPUT_SYMBOLS: usize = 1_000_000;
pub const DEFAULT_MAX_OUTPUT_IMPORTS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuzzLimits {
    pub max_input_bytes: usize,
    pub max_segments: usize,
    pub max_seeds: usize,
    pub max_symbols: usize,
    pub max_imports: usize,
}

impl Default for FuzzLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_FUZZ_INPUT_BYTES,
            max_segments: DEFAULT_MAX_OUTPUT_SEGMENTS,
            max_seeds: DEFAULT_MAX_OUTPUT_SEEDS,
            max_symbols: DEFAULT_MAX_OUTPUT_SYMBOLS,
            max_imports: DEFAULT_MAX_OUTPUT_IMPORTS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedImageSummary {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub base_address: Address,
    pub entry_point: Option<Address>,
    pub segment_count: usize,
    pub seed_count: usize,
    pub symbol_count: usize,
    pub import_count: usize,
}

/// Fuzz harness entry point for raw byte slices with bounded input size.
///
/// Guarantees:
/// - Enforces bounded memory allocation proportional to `limits.max_input_bytes`.
/// - No panics, integer overflows, or uncontrolled loops.
/// - No network or broad filesystem effects (pure in-memory parsing).
/// - Validates parsed invariants (segments, entrypoint, arithmetic) before returning.
/// - Returns `Ok(BoundedImageSummary)` on success or typed `Err(LoadError)` on failure.
pub fn fuzz_loader_slice(
    bytes: &[u8],
    limits: FuzzLimits,
) -> Result<BoundedImageSummary, LoadError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(LoadError::InputTooLarge {
            size: bytes.len(),
            limit: limits.max_input_bytes,
        });
    }

    let image = GoblinLoader.load(Arc::from(bytes))?;

    if image.segments.len() > limits.max_segments {
        return Err(LoadError::Malformed(
            "segment count exceeds safety limit".to_string(),
        ));
    }
    if image.function_seeds.len() > limits.max_seeds {
        return Err(LoadError::Malformed(
            "function seed count exceeds safety limit".to_string(),
        ));
    }
    if image.symbols.len() > limits.max_symbols {
        return Err(LoadError::Malformed(
            "symbol count exceeds safety limit".to_string(),
        ));
    }
    if image.imports.len() > limits.max_imports {
        return Err(LoadError::Malformed(
            "import count exceeds safety limit".to_string(),
        ));
    }

    for segment in &image.segments {
        if segment.address.0.checked_add(segment.file_size).is_none() {
            return Err(LoadError::Malformed(
                "segment virtual file-span arithmetic overflows".to_string(),
            ));
        }
        if segment.address.0.checked_add(segment.memory_size).is_none() {
            return Err(LoadError::Malformed(
                "segment virtual memory-span arithmetic overflows".to_string(),
            ));
        }
        if segment.file_offset.checked_add(segment.file_size).is_none() {
            return Err(LoadError::Malformed(
                "segment file offset range arithmetic overflows".to_string(),
            ));
        }
        let _ = image.bytes_at(segment.address, 1);
    }

    if let Some(entry) = image.entry_point {
        let _ = image.bytes_at(entry, 1);
        let _ = image.import_thunk_at(entry);
    }

    Ok(BoundedImageSummary {
        format: image.format,
        architecture: image.architecture,
        base_address: image.base_address,
        entry_point: image.entry_point,
        segment_count: image.segments.len(),
        seed_count: image.function_seeds.len(),
        symbol_count: image.symbols.len(),
        import_count: image.imports.len(),
    })
}

/// Convenience fuzz target entry point with default limits.
pub fn fuzz_target(data: &[u8]) -> Result<BoundedImageSummary, LoadError> {
    fuzz_loader_slice(data, FuzzLimits::default())
}

pub fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    if let Some(end) = offset.checked_add(2).filter(|end| *end <= bytes.len()) {
        bytes[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

pub fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    if let Some(end) = offset.checked_add(4).filter(|end| *end <= bytes.len()) {
        bytes[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

pub fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    if let Some(end) = offset.checked_add(8).filter(|end| *end <= bytes.len()) {
        bytes[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

pub fn minimal_elf64() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x79];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT

    put_u16(&mut bytes, 0x10, 2); // ET_EXEC
    put_u16(&mut bytes, 0x12, 0x3e); // EM_X86_64
    put_u32(&mut bytes, 0x14, 1); // EV_CURRENT
    put_u64(&mut bytes, 0x18, 0x400000); // e_entry
    put_u64(&mut bytes, 0x20, 0x40); // e_phoff
    put_u16(&mut bytes, 0x34, 64); // e_ehsize
    put_u16(&mut bytes, 0x36, 56); // e_phentsize
    put_u16(&mut bytes, 0x38, 1); // e_phnum

    put_u32(&mut bytes, 0x40, 1); // PT_LOAD
    put_u32(&mut bytes, 0x44, 5); // PF_R | PF_X
    put_u64(&mut bytes, 0x48, 0x78); // p_offset
    put_u64(&mut bytes, 0x50, 0x400000); // p_vaddr
    put_u64(&mut bytes, 0x58, 0x400000); // p_paddr
    put_u64(&mut bytes, 0x60, 1); // p_filesz
    put_u64(&mut bytes, 0x68, 1); // p_memsz
    put_u64(&mut bytes, 0x70, 0x1000); // p_align
    bytes[0x78] = 0xc3; // RET

    bytes
}

pub fn minimal_elf32_x86() -> Vec<u8> {
    let mut bytes = vec![0_u8; 52];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1; // ELFCLASS32
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    put_u16(&mut bytes, 0x10, 2);
    put_u16(&mut bytes, 0x12, 3); // EM_386
    put_u32(&mut bytes, 0x14, 1);
    put_u16(&mut bytes, 0x28, 52);

    bytes
}

pub fn minimal_pe32_plus() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    let pe_offset = 0x80;
    let coff = pe_offset + 4;
    let optional = coff + 20;
    let section = optional + 0xf0;

    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, pe_offset as u32);
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, coff, 0x8664); // COFF_MACHINE_X86_64
    put_u16(&mut bytes, coff + 2, 1); // NumberOfSections = 1
    put_u16(&mut bytes, coff + 16, 0xf0); // SizeOfOptionalHeader
    put_u16(&mut bytes, coff + 18, 0x22); // Characteristics

    put_u16(&mut bytes, optional, 0x20b); // PE32+ magic
    put_u32(&mut bytes, optional + 16, 0x1000); // AddressOfEntryPoint
    put_u32(&mut bytes, optional + 20, 0x1000); // BaseOfCode
    put_u64(&mut bytes, optional + 24, 0x140000000); // ImageBase
    put_u32(&mut bytes, optional + 32, 0x1000); // SectionAlignment
    put_u32(&mut bytes, optional + 36, 0x200); // FileAlignment
    put_u32(&mut bytes, optional + 56, 0x2000); // SizeOfImage
    put_u32(&mut bytes, optional + 60, 0x200); // SizeOfHeaders
    put_u16(&mut bytes, optional + 68, 3); // Subsystem (Windows CUI)
    put_u64(&mut bytes, optional + 72, 0x100000); // SizeOfStackReserve
    put_u64(&mut bytes, optional + 80, 0x1000); // SizeOfStackCommit
    put_u64(&mut bytes, optional + 88, 0x100000); // SizeOfHeapReserve
    put_u64(&mut bytes, optional + 96, 0x1000); // SizeOfHeapCommit
    put_u32(&mut bytes, optional + 108, 16); // NumberOfRvaAndSizes

    bytes[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut bytes, section + 8, 1); // VirtualSize
    put_u32(&mut bytes, section + 12, 0x1000); // VirtualAddress
    put_u32(&mut bytes, section + 16, 0x200); // SizeOfRawData
    put_u32(&mut bytes, section + 20, 0x200); // PointerToRawData
    put_u32(&mut bytes, section + 36, 0x60000020); // Characteristics (code, read, execute)
    bytes[0x200] = 0xc3; // RET

    bytes
}

#[derive(Clone, Debug)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub const fn seeded(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x853c_49e6_748f_ea9b
            } else {
                seed
            },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut x = self.state;
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94d049bb133111eb);
        x ^ (x >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (self.next_u64() as usize) % max
        }
    }

    pub fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next_u8();
        }
    }
}

pub const BOUNDARY_U64: [u64; 9] = [
    0,
    1,
    0x7fff_ffff,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ff00,
    0xffff_ffff_ffff_fffe,
    u64::MAX,
];

pub const BOUNDARY_U32: [u32; 8] = [0, 1, 0x7f, 0xff, 0x7fff, 0xffff, 0x7fff_ffff, u32::MAX];

pub const BOUNDARY_U16: [u16; 6] = [0, 1, 0x3e, 0x8664, 0x7fff, u16::MAX];

pub const BOUNDARY_BYTES: [u8; 8] = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0xaa, 0x55];

/// Deterministically mutate a byte buffer for fuzz/boundary testing.
pub fn mutate_slice(input: &[u8], rng: &mut DeterministicRng) -> Vec<u8> {
    if input.is_empty() {
        let len = rng.next_usize(64) + 1;
        let mut buf = vec![0_u8; len];
        rng.fill_bytes(&mut buf);
        return buf;
    }

    let mut mutated = input.to_vec();
    let action = rng.next_usize(6);

    match action {
        0 => {
            // Flip a bit
            let index = rng.next_usize(mutated.len());
            let bit = 1 << rng.next_usize(8);
            mutated[index] ^= bit;
        }
        1 => {
            // Overwrite byte with boundary value
            let index = rng.next_usize(mutated.len());
            let val = BOUNDARY_BYTES[rng.next_usize(BOUNDARY_BYTES.len())];
            mutated[index] = val;
        }
        2 => {
            // Overwrite 32-bit integer at random aligned/unaligned offset with boundary value
            if mutated.len() >= 4 {
                let max_offset = mutated.len() - 4;
                let offset = rng.next_usize(max_offset + 1);
                let val = BOUNDARY_U32[rng.next_usize(BOUNDARY_U32.len())];
                put_u32(&mut mutated, offset, val);
            }
        }
        3 => {
            // Overwrite 64-bit integer at random offset with boundary value
            if mutated.len() >= 8 {
                let max_offset = mutated.len() - 8;
                let offset = rng.next_usize(max_offset + 1);
                let val = BOUNDARY_U64[rng.next_usize(BOUNDARY_U64.len())];
                put_u64(&mut mutated, offset, val);
            }
        }
        4 => {
            // Truncate to random length
            let new_len = rng.next_usize(mutated.len());
            mutated.truncate(new_len);
        }
        _ => {
            // Shuffle/swap two bytes
            if mutated.len() >= 2 {
                let i = rng.next_usize(mutated.len());
                let j = rng.next_usize(mutated.len());
                mutated.swap(i, j);
            }
        }
    }

    mutated
}
