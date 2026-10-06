#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use goblin::Object;
use goblin::elf::header::{EM_AARCH64, EM_X86_64};
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::sym::{STT_FUNC, STT_OBJECT, st_type};
use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86_64};
use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use radare3_image::{
    BinaryData, BinaryImage, FunctionSeed, FunctionSeedKind, Permissions, Segment, Symbol,
    SymbolKind,
};
use radare3_types::{Address, Architecture, BinaryFormat};

pub const LOADER_SEMANTICS_VERSION: &str = "goblin-0.10.7/radare3-loader-v2-symbols";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoadError {
    Malformed(String),
    UnsupportedFormat,
    UnsupportedClass,
    UnsupportedArchitecture(u16),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(f, "malformed binary: {message}"),
            Self::UnsupportedFormat => write!(f, "unsupported binary format"),
            Self::UnsupportedClass => {
                write!(f, "only 64-bit ELF and PE32+ are currently supported")
            }
            Self::UnsupportedArchitecture(machine) => {
                write!(f, "unsupported machine type: 0x{machine:04x}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

pub trait Loader: Send + Sync {
    fn load_data(&self, bytes: BinaryData) -> Result<BinaryImage, LoadError>;

    fn load(&self, bytes: Arc<[u8]>) -> Result<BinaryImage, LoadError> {
        self.load_data(BinaryData::owned(bytes))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GoblinLoader;

impl Loader for GoblinLoader {
    fn load_data(&self, bytes: BinaryData) -> Result<BinaryImage, LoadError> {
        let object = Object::parse(bytes.as_slice())
            .map_err(|error| LoadError::Malformed(error.to_string()))?;

        match object {
            Object::Elf(elf) => load_elf(bytes.clone(), &elf),
            Object::PE(pe) => load_pe(bytes.clone(), &pe),
            _ => Err(LoadError::UnsupportedFormat),
        }
    }
}

fn load_elf(bytes: BinaryData, elf: &goblin::elf::Elf<'_>) -> Result<BinaryImage, LoadError> {
    if !elf.is_64 {
        return Err(LoadError::UnsupportedClass);
    }

    let architecture = match elf.header.e_machine {
        EM_X86_64 => Architecture::X86_64,
        EM_AARCH64 => Architecture::Arm64,
        machine => return Err(LoadError::UnsupportedArchitecture(machine)),
    };

    let segments: Vec<Segment> = elf
        .program_headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.p_type == PT_LOAD)
        .map(|(index, header)| Segment {
            name: format!("LOAD{index}"),
            address: Address(header.p_vaddr),
            file_offset: header.p_offset,
            file_size: header.p_filesz,
            memory_size: header.p_memsz,
            permissions: Permissions {
                read: header.is_read(),
                write: header.is_write(),
                execute: header.is_executable(),
            },
        })
        .collect();

    if segments.is_empty() {
        return Err(LoadError::Malformed(
            "ELF contains no loadable program segments".to_string(),
        ));
    }

    let base_address = segments
        .iter()
        .map(|segment| segment.address.0)
        .min()
        .map(Address)
        .unwrap_or(Address(0));

    let entry_point = (elf.entry != 0).then_some(Address(elf.entry));
    let mut seeds = Vec::new();
    let mut symbols = Vec::new();

    for symbol in elf.syms.iter() {
        if st_type(symbol.st_info) != STT_FUNC || symbol.st_value == 0 {
            continue;
        }

        let name = elf
            .strtab
            .get_at(symbol.st_name)
            .filter(|name| !name.is_empty())
            .map(str::to_owned);

        seeds.push(FunctionSeed {
            address: Address(symbol.st_value),
            kind: FunctionSeedKind::Symbol,
            name: name.clone(),
        });

        if let Some(name) = name {
            symbols.push(Symbol {
                address: Address(symbol.st_value),
                size: symbol.st_size,
                kind: SymbolKind::Function,
                name,
            });
        }
    }

    for symbol in elf.dynsyms.iter() {
        if st_type(symbol.st_info) != STT_FUNC || symbol.st_value == 0 {
            continue;
        }

        let name = elf
            .dynstrtab
            .get_at(symbol.st_name)
            .filter(|name| !name.is_empty())
            .map(str::to_owned);

        seeds.push(FunctionSeed {
            address: Address(symbol.st_value),
            kind: FunctionSeedKind::Symbol,
            name: name.clone(),
        });

        if let Some(name) = name {
            symbols.push(Symbol {
                address: Address(symbol.st_value),
                size: symbol.st_size,
                kind: SymbolKind::Function,
                name,
            });
        }
    }

    collect_elf_non_function_symbols(elf.syms.iter(), &elf.strtab, &mut symbols);
    collect_elf_non_function_symbols(elf.dynsyms.iter(), &elf.dynstrtab, &mut symbols);

    Ok(BinaryImage::from_data(
        bytes,
        BinaryFormat::Elf,
        architecture,
        base_address,
        entry_point,
        segments,
    )
    .with_function_seeds(seeds)
    .with_symbols(symbols))
}

fn collect_elf_non_function_symbols<'a>(
    symbols: impl Iterator<Item = goblin::elf::sym::Sym>,
    strings: &goblin::strtab::Strtab<'a>,
    out: &mut Vec<Symbol>,
) {
    for symbol in symbols {
        if symbol.st_value == 0 || st_type(symbol.st_info) == STT_FUNC {
            continue;
        }

        let Some(name) = strings
            .get_at(symbol.st_name)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };

        out.push(Symbol {
            address: Address(symbol.st_value),
            size: symbol.st_size,
            kind: if st_type(symbol.st_info) == STT_OBJECT {
                SymbolKind::Object
            } else {
                SymbolKind::Other
            },
            name: name.to_owned(),
        });
    }
}

fn load_pe(bytes: BinaryData, pe: &goblin::pe::PE<'_>) -> Result<BinaryImage, LoadError> {
    if !pe.is_64 {
        return Err(LoadError::UnsupportedClass);
    }

    let machine = pe.header.coff_header.machine;
    let architecture = match machine {
        COFF_MACHINE_X86_64 => Architecture::X86_64,
        COFF_MACHINE_ARM64 => Architecture::Arm64,
        machine => return Err(LoadError::UnsupportedArchitecture(machine)),
    };

    let segments: Vec<Segment> = pe
        .sections
        .iter()
        .enumerate()
        .map(|(index, section)| {
            let name = section
                .name()
                .map(str::to_owned)
                .unwrap_or_else(|_| format!("section{index}"));
            let memory_size = if section.virtual_size == 0 {
                u64::from(section.size_of_raw_data)
            } else {
                u64::from(section.virtual_size)
            };

            Segment {
                name,
                address: Address(pe.image_base + u64::from(section.virtual_address)),
                file_offset: u64::from(section.pointer_to_raw_data),
                file_size: u64::from(section.size_of_raw_data),
                memory_size,
                permissions: Permissions {
                    read: section.characteristics & IMAGE_SCN_MEM_READ != 0,
                    write: section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    execute: section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                },
            }
        })
        .collect();

    if segments.is_empty() {
        return Err(LoadError::Malformed("PE contains no sections".to_string()));
    }

    let entry_point = (pe.entry != 0)
        .then(|| pe.image_base.checked_add(u64::from(pe.entry)))
        .flatten()
        .map(Address);

    let mut seeds = Vec::new();
    let mut symbols = Vec::new();

    for export in &pe.exports {
        if export.reexport.is_some() || export.rva == 0 {
            continue;
        }

        let Ok(rva) = u64::try_from(export.rva) else {
            continue;
        };
        let Some(address) = pe.image_base.checked_add(rva).map(Address) else {
            continue;
        };

        let name = export.name.map(str::to_owned);

        seeds.push(FunctionSeed {
            address,
            kind: FunctionSeedKind::Export,
            name: name.clone(),
        });

        if let Some(name) = name {
            symbols.push(Symbol {
                address,
                size: 0,
                kind: SymbolKind::Export,
                name,
            });
        }
    }

    if architecture == Architecture::X86_64 {
        collect_pe_runtime_function_seeds(bytes.as_slice(), pe, &mut seeds);
    }

    Ok(BinaryImage::from_data(
        bytes,
        BinaryFormat::Pe,
        architecture,
        Address(pe.image_base),
        entry_point,
        segments,
    )
    .with_function_seeds(seeds)
    .with_symbols(symbols))
}

fn collect_pe_runtime_function_seeds(
    bytes: &[u8],
    pe: &goblin::pe::PE<'_>,
    seeds: &mut Vec<FunctionSeed>,
) {
    for section in &pe.sections {
        if section.name().ok() != Some(".pdata") {
            continue;
        }

        let Ok(start) = usize::try_from(section.pointer_to_raw_data) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.size_of_raw_data) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        let Some(data) = bytes.get(start..end) else {
            continue;
        };

        for record in data.chunks_exact(12) {
            let begin_rva = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
            if begin_rva == 0 {
                continue;
            }

            let Some(address) = pe.image_base.checked_add(u64::from(begin_rva)).map(Address) else {
                continue;
            };

            seeds.push(FunctionSeed {
                address,
                kind: FunctionSeedKind::ExceptionTable,
                name: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_elf64() -> Arc<[u8]> {
        let mut bytes = vec![0_u8; 0x79];

        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;

        put_u16(&mut bytes, 0x10, 2);
        put_u16(&mut bytes, 0x12, EM_X86_64);
        put_u32(&mut bytes, 0x14, 1);
        put_u64(&mut bytes, 0x18, 0x400000);
        put_u64(&mut bytes, 0x20, 0x40);
        put_u16(&mut bytes, 0x34, 64);
        put_u16(&mut bytes, 0x36, 56);
        put_u16(&mut bytes, 0x38, 1);

        put_u32(&mut bytes, 0x40, PT_LOAD);
        put_u32(&mut bytes, 0x44, 5);
        put_u64(&mut bytes, 0x48, 0x78);
        put_u64(&mut bytes, 0x50, 0x400000);
        put_u64(&mut bytes, 0x58, 0x400000);
        put_u64(&mut bytes, 0x60, 1);
        put_u64(&mut bytes, 0x68, 1);
        put_u64(&mut bytes, 0x70, 0x1000);
        bytes[0x78] = 0xc3;

        Arc::from(bytes)
    }

    fn minimal_pe32_plus() -> Arc<[u8]> {
        let mut bytes = vec![0_u8; 0x400];
        let pe_offset = 0x80;
        let coff = pe_offset + 4;
        let optional = coff + 20;
        let section = optional + 0xf0;

        bytes[0..2].copy_from_slice(b"MZ");
        put_u32(&mut bytes, 0x3c, pe_offset as u32);
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        put_u16(&mut bytes, coff, COFF_MACHINE_X86_64);
        put_u16(&mut bytes, coff + 2, 1);
        put_u16(&mut bytes, coff + 16, 0xf0);
        put_u16(&mut bytes, coff + 18, 0x22);

        put_u16(&mut bytes, optional, 0x20b);
        put_u32(&mut bytes, optional + 16, 0x1000);
        put_u32(&mut bytes, optional + 20, 0x1000);
        put_u64(&mut bytes, optional + 24, 0x140000000);
        put_u32(&mut bytes, optional + 32, 0x1000);
        put_u32(&mut bytes, optional + 36, 0x200);
        put_u32(&mut bytes, optional + 56, 0x2000);
        put_u32(&mut bytes, optional + 60, 0x200);
        put_u16(&mut bytes, optional + 68, 3);
        put_u64(&mut bytes, optional + 72, 0x100000);
        put_u64(&mut bytes, optional + 80, 0x1000);
        put_u64(&mut bytes, optional + 88, 0x100000);
        put_u64(&mut bytes, optional + 96, 0x1000);
        put_u32(&mut bytes, optional + 108, 16);

        bytes[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut bytes, section + 8, 1);
        put_u32(&mut bytes, section + 12, 0x1000);
        put_u32(&mut bytes, section + 16, 0x200);
        put_u32(&mut bytes, section + 20, 0x200);
        put_u32(&mut bytes, section + 36, 0x60000020);
        bytes[0x200] = 0xc3;

        Arc::from(bytes)
    }

    #[test]
    fn loads_minimal_elf64() -> Result<(), Box<dyn std::error::Error>> {
        let image = GoblinLoader.load(minimal_elf64())?;

        assert_eq!(image.format, BinaryFormat::Elf);
        assert_eq!(image.architecture, Architecture::X86_64);
        assert_eq!(image.base_address, Address(0x400000));
        assert_eq!(image.entry_point, Some(Address(0x400000)));
        assert_eq!(image.segments.len(), 1);
        assert_eq!(image.function_seeds.len(), 1);
        assert_eq!(image.bytes_at(Address(0x400000), 15), Some(&[0xc3][..]));

        Ok(())
    }

    #[test]
    fn loads_minimal_pe32_plus() -> Result<(), Box<dyn std::error::Error>> {
        let image = GoblinLoader.load(minimal_pe32_plus())?;

        assert_eq!(image.format, BinaryFormat::Pe);
        assert_eq!(image.architecture, Architecture::X86_64);
        assert_eq!(image.base_address, Address(0x140000000));
        assert_eq!(image.entry_point, Some(Address(0x140001000)));
        assert_eq!(image.segments.len(), 1);
        assert_eq!(image.function_seeds.len(), 1);
        let code = image
            .bytes_at(Address(0x140001000), 15)
            .ok_or("expected file-backed PE entry point")?;
        assert_eq!(code.len(), 15);
        assert_eq!(code[0], 0xc3);

        Ok(())
    }
}
