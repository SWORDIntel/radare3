#![forbid(unsafe_code)]

use std::sync::Arc;

use radare3::arch::Decoder;
use radare3::arch_x86::IcedX86Decoder;
use radare3::loader::{GoblinLoader, Loader};
use radare3::types::{Address, Architecture};

fn main() {
    let mut args = std::env::args();
    let _program = args.next();

    let result = match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("radare3 {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some("info") => match args.next() {
            Some(path) => info(&path),
            None => Err("info requires a file path".to_string()),
        },
        Some("decode") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => decode(&path, &address),
            _ => Err("decode requires a file path and virtual address".to_string()),
        },
        Some(other) => Err(format!("unsupported command: {other}")),
    };

    if let Err(error) = result {
        eprintln!("radare3: {error}");
        std::process::exit(2);
    }
}

fn print_help() {
    println!(
        "radare3 {}\n\nUsage:\n  radare3 info <file>\n  radare3 decode <file> <address>\n  radare3 --version",
        env!("CARGO_PKG_VERSION")
    );
}

fn load(path: &str) -> Result<radare3::image::BinaryImage, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?;
    GoblinLoader
        .load(Arc::from(bytes))
        .map_err(|error| error.to_string())
}

fn info(path: &str) -> Result<(), String> {
    let image = load(path)?;

    println!("format: {:?}", image.format);
    println!("architecture: {:?}", image.architecture);
    println!("base: {}", image.base_address);
    match image.entry_point {
        Some(entry) => println!("entry: {entry}"),
        None => println!("entry: none"),
    }
    println!("segments: {}", image.segments.len());

    for segment in &image.segments {
        println!(
            "  {} {} file=0x{:x}+0x{:x} mem=0x{:x} r{}w{}x{}",
            segment.name,
            segment.address,
            segment.file_offset,
            segment.file_size,
            segment.memory_size,
            u8::from(segment.permissions.read),
            u8::from(segment.permissions.write),
            u8::from(segment.permissions.execute),
        );
    }

    Ok(())
}

fn decode(path: &str, address: &str) -> Result<(), String> {
    let image = load(path)?;
    if image.architecture != Architecture::X86_64 {
        return Err(format!(
            "decode currently supports x86-64 only, got {:?}",
            image.architecture
        ));
    }

    let address = parse_address(address)?;
    let bytes = image
        .bytes_at(address, 15)
        .ok_or_else(|| format!("address {address} is not file-backed"))?;
    let decoded = IcedX86Decoder::x86_64()
        .decode(address, bytes)
        .map_err(|error| format!("decode failed: {error:?}"))?;

    println!(
        "{} len={} flow={:?} target={}",
        decoded.address,
        decoded.length,
        decoded.flow,
        decoded
            .target
            .map(|target| target.to_string())
            .unwrap_or_else(|| "none".to_string())
    );

    Ok(())
}

fn parse_address(value: &str) -> Result<Address, String> {
    let value = value.trim();
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };

    parsed
        .map(Address)
        .map_err(|error| format!("invalid address {value}: {error}"))
}
