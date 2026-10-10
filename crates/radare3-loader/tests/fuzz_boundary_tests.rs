#![forbid(unsafe_code)]

use radare3_loader::fuzz::{
    BOUNDARY_U16, BOUNDARY_U32, BOUNDARY_U64, DeterministicRng, FuzzLimits, fuzz_loader_slice,
    fuzz_target, minimal_elf64, minimal_pe32_plus, mutate_slice, put_u16, put_u32, put_u64,
};
use radare3_loader::{DEFAULT_MAX_LOADER_INPUT_BYTES, LoadError};
use radare3_types::{Architecture, BinaryFormat};

#[test]
fn rejects_oversized_inputs_without_allocation() {
    let limits = FuzzLimits {
        max_input_bytes: 64,
        ..FuzzLimits::default()
    };
    let data = vec![0x90_u8; 65];

    assert_eq!(
        fuzz_loader_slice(&data, limits),
        Err(LoadError::InputTooLarge {
            size: 65,
            limit: 64,
        })
    );

    let data_64 = vec![0x90_u8; 64];
    assert_ne!(
        fuzz_loader_slice(&data_64, limits),
        Err(LoadError::InputTooLarge {
            size: 64,
            limit: 64,
        })
    );
}

#[test]
fn mutation_helpers_ignore_offsets_that_would_overflow() {
    let mut bytes = [0_u8; 8];
    put_u16(&mut bytes, usize::MAX, 0x1234);
    put_u32(&mut bytes, usize::MAX, 0x1234_5678);
    put_u64(&mut bytes, usize::MAX, 0x1234_5678_9abc_def0);
    assert_eq!(bytes, [0; 8]);
}

#[test]
fn loader_enforces_default_max_input_bytes() {
    let limits = FuzzLimits {
        max_input_bytes: 128,
        ..FuzzLimits::default()
    };
    let oversized = vec![0_u8; 129];
    assert_eq!(
        fuzz_loader_slice(&oversized, limits),
        Err(LoadError::InputTooLarge {
            size: 129,
            limit: 128,
        })
    );
    assert_eq!(DEFAULT_MAX_LOADER_INPUT_BYTES, 512 * 1024 * 1024);
}

#[test]
fn truncated_elf64_prefixes_never_panic() {
    let base = minimal_elf64();

    assert!(fuzz_target(&[]).is_err());

    for end in 0..base.len() {
        let prefix = &base[..end];
        let result = fuzz_target(prefix);
        match result {
            Ok(summary) => {
                assert!(summary.segment_count <= 10);
            }
            Err(err) => {
                assert!(!err.to_string().is_empty());
            }
        }
    }

    let full_result = fuzz_target(&base);
    assert!(full_result.is_ok(), "complete minimal ELF64 must parse");
    if let Ok(summary) = full_result {
        assert_eq!(summary.format, BinaryFormat::Elf);
        assert_eq!(summary.architecture, Architecture::X86_64);
        assert_eq!(summary.segment_count, 1);
        assert_eq!(summary.seed_count, 1);
    }
}

#[test]
fn truncated_pe32_plus_prefixes_never_panic() {
    let base = minimal_pe32_plus();

    assert!(fuzz_target(&[]).is_err());

    for end in 0..base.len() {
        let prefix = &base[..end];
        let result = fuzz_target(prefix);
        match result {
            Ok(summary) => {
                assert!(summary.segment_count <= 10);
            }
            Err(err) => {
                assert!(!err.to_string().is_empty());
            }
        }
    }

    let full_result = fuzz_target(&base);
    assert!(full_result.is_ok(), "complete minimal PE32+ must parse");
    if let Ok(summary) = full_result {
        assert_eq!(summary.format, BinaryFormat::Pe);
        assert_eq!(summary.architecture, Architecture::X86_64);
        assert_eq!(summary.segment_count, 1);
        assert_eq!(summary.seed_count, 1);
    }
}

#[test]
fn pe_virtual_address_overflow_is_safely_rejected() {
    let mut base = minimal_pe32_plus();
    let pe_offset = 0x80;
    let optional = pe_offset + 24;

    // Set ImageBase to u64::MAX so image_base + section.virtual_address overflows
    put_u64(&mut base, optional + 24, u64::MAX);

    let result = fuzz_target(&base);
    assert!(
        matches!(result, Err(LoadError::Malformed(ref msg)) if msg.contains("overflows address space")),
        "expected LoadError::Malformed with overflow message, got: {result:?}"
    );

    // Set ImageBase near u64::MAX where image_base + virtual_address wraps
    put_u64(&mut base, optional + 24, u64::MAX - 0x10);
    let section = optional + 0xf0;
    put_u32(&mut base, section + 12, 0x1000);

    let result2 = fuzz_target(&base);
    assert!(
        matches!(result2, Err(LoadError::Malformed(ref msg)) if msg.contains("overflows address space")),
        "expected LoadError::Malformed with overflow message, got: {result2:?}"
    );
}

#[test]
fn elf_segment_range_overflow_is_safely_rejected() {
    let mut base = minimal_elf64();

    // Set program header p_vaddr to u64::MAX with non-zero p_filesz
    put_u64(&mut base, 0x50, u64::MAX);
    put_u64(&mut base, 0x60, 100);

    let result = fuzz_target(&base);
    assert!(
        matches!(result, Err(LoadError::Malformed(ref msg)) if msg.contains("overflows address space")),
        "expected LoadError::Malformed with overflow message, got: {result:?}"
    );

    // Reset p_vaddr and set overflowing p_offset
    let mut base2 = minimal_elf64();
    put_u64(&mut base2, 0x48, u64::MAX);
    put_u64(&mut base2, 0x60, 100);

    let result2 = fuzz_target(&base2);
    assert!(
        matches!(result2, Err(LoadError::Malformed(ref msg)) if msg.contains("overflows address space")),
        "expected LoadError::Malformed with overflow message, got: {result2:?}"
    );
}

#[test]
fn mutated_elf_header_fields_never_panic() {
    let base = minimal_elf64();

    // Test ELF class boundary values (offset 4)
    for class in [0_u8, 1, 2, 3, 0x7f, 0xff] {
        let mut mutated = base.clone();
        mutated[4] = class;
        let res = fuzz_target(&mutated);
        if class != 2 {
            assert!(res.is_err(), "non-64 class {class} must be rejected");
        }
    }

    // Test machine architecture field (offset 0x12)
    for machine in [0_u16, 3, 0x3e, 0xb7, 0x1234, u16::MAX] {
        let mut mutated = base.clone();
        put_u16(&mut mutated, 0x12, machine);
        let res = fuzz_target(&mutated);
        if machine != 0x3e && machine != 0xb7 {
            if let Err(LoadError::UnsupportedArchitecture(m)) = res {
                assert_eq!(m, machine);
            }
        }
    }

    // Test program header offset and count boundaries
    for phoff in BOUNDARY_U64 {
        let mut mutated = base.clone();
        put_u64(&mut mutated, 0x20, phoff);
        let _ = fuzz_target(&mutated);
    }

    for phnum in BOUNDARY_U16 {
        let mut mutated = base.clone();
        put_u16(&mut mutated, 0x38, phnum);
        let res = fuzz_target(&mutated);
        if phnum == 0 {
            assert_eq!(
                res.as_ref().err(),
                Some(&LoadError::Malformed(
                    "ELF contains no loadable program segments".to_string()
                ))
            );
        }
    }
}

#[test]
fn mutated_pe_header_fields_never_panic() {
    let base = minimal_pe32_plus();
    let pe_offset = 0x80;
    let coff = pe_offset + 4;
    let optional = coff + 20;

    // Test e_lfanew pointer boundaries
    for lfanew in BOUNDARY_U32 {
        let mut mutated = base.clone();
        put_u32(&mut mutated, 0x3c, lfanew);
        let _ = fuzz_target(&mutated);
    }

    // Test COFF machine boundaries
    for machine in [0_u16, 0x14c, 0x8664, 0xaa64, u16::MAX] {
        let mut mutated = base.clone();
        put_u16(&mut mutated, coff, machine);
        let res = fuzz_target(&mutated);
        if machine != 0x8664 && machine != 0xaa64 {
            assert!(res.is_err());
        }
    }

    // Test section count boundaries
    for num_sections in [0_u16, 1, 2, 0x7fff, u16::MAX] {
        let mut mutated = base.clone();
        put_u16(&mut mutated, coff + 2, num_sections);
        let res = fuzz_target(&mutated);
        if num_sections == 0 {
            assert_eq!(
                res.as_ref().err(),
                Some(&LoadError::Malformed("PE contains no sections".to_string()))
            );
        }
    }

    // Test optional header magic
    for magic in [0_u16, 0x10b, 0x20b, u16::MAX] {
        let mut mutated = base.clone();
        put_u16(&mut mutated, optional, magic);
        let res = fuzz_target(&mutated);
        if magic == 0x10b {
            assert_eq!(res.as_ref().err(), Some(&LoadError::UnsupportedClass));
        }
    }

    // Test ImageBase boundary values
    for image_base in BOUNDARY_U64 {
        let mut mutated = base.clone();
        put_u64(&mut mutated, optional + 24, image_base);
        let _ = fuzz_target(&mutated);
    }
}

#[test]
fn pe_pdata_exception_table_boundaries_never_panic() {
    let mut base = minimal_pe32_plus();
    let pe_offset = 0x80;
    let coff = pe_offset + 4;
    let optional = coff + 20;
    let section1 = optional + 0xf0;
    let section2 = section1 + 40;

    put_u16(&mut base, coff + 2, 2);
    base.resize(0x500, 0);

    base[section2..section2 + 6].copy_from_slice(b".pdata");
    put_u32(&mut base, section2 + 8, 24);
    put_u32(&mut base, section2 + 12, 0x2000);
    put_u32(&mut base, section2 + 16, 24);
    put_u32(&mut base, section2 + 20, 0x240);
    put_u32(&mut base, section2 + 36, 0x40000040);

    put_u32(&mut base, 0x240, 0x1000);
    put_u32(&mut base, 0x244, 0x1010);
    put_u32(&mut base, 0x248, 0x1020);

    put_u32(&mut base, 0x24c, u32::MAX);
    put_u32(&mut base, 0x250, 0);
    put_u32(&mut base, 0x254, 0);

    let res = fuzz_target(&base);
    assert!(res.is_ok(), "PE with .pdata records must parse safely");
    if let Ok(summary) = res {
        assert_eq!(summary.segment_count, 2);
        assert!(summary.seed_count >= 1);
    }

    put_u32(&mut base, section2 + 16, 17);
    let res_odd = fuzz_target(&base);
    assert!(res_odd.is_ok());

    put_u32(&mut base, section2 + 20, 0xffff);
    let res_oob = fuzz_target(&base);
    assert!(res_oob.is_ok());
}

#[test]
fn deterministic_property_fuzz_campaign() {
    let mut rng = DeterministicRng::seeded(0x5EED_CAFE_B007);
    let elf_seed = minimal_elf64();
    let pe_seed = minimal_pe32_plus();
    let limits = FuzzLimits::default();

    let mut ok_count = 0_usize;
    let mut err_count = 0_usize;

    for iteration in 0..1000 {
        let input = match iteration % 4 {
            0 => {
                let len = rng.next_usize(512);
                let mut buf = vec![0_u8; len];
                rng.fill_bytes(&mut buf);
                buf
            }
            1 => mutate_slice(&elf_seed, &mut rng),
            2 => mutate_slice(&pe_seed, &mut rng),
            _ => {
                let mut buf = elf_seed.clone();
                let splice_point = rng.next_usize(buf.len().min(pe_seed.len()));
                buf.splice(..splice_point, pe_seed[..splice_point].iter().copied());
                mutate_slice(&buf, &mut rng)
            }
        };

        match fuzz_loader_slice(&input, limits) {
            Ok(summary) => {
                ok_count += 1;
                assert!(summary.segment_count <= limits.max_segments);
                assert!(summary.seed_count <= limits.max_seeds);
                assert!(summary.symbol_count <= limits.max_symbols);
                assert!(summary.import_count <= limits.max_imports);
                assert!(summary.format == BinaryFormat::Elf || summary.format == BinaryFormat::Pe);
                assert!(
                    summary.architecture == Architecture::X86_64
                        || summary.architecture == Architecture::Arm64
                );
            }
            Err(err) => {
                err_count += 1;
                let msg = err.to_string();
                assert!(!msg.is_empty(), "error message must not be empty");
            }
        }
    }

    assert!(
        ok_count > 0,
        "fuzz campaign should have some passing inputs"
    );
    assert!(err_count > 0, "fuzz campaign should have failing inputs");
}
