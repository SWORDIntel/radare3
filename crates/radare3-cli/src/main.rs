#![forbid(unsafe_code)]

use radare3::analysis::{
    AnalysisOptions, AnalysisResult, Analyzer, ParallelAnalyzer, RecursiveAnalyzer,
};
use radare3::arch::Decoder;
use radare3::arch_x86::{DECODER_SEMANTICS_VERSION, IcedX86Decoder};
use radare3::cache::{
    AnalysisCache, AnalysisSnapshot, CacheError, CacheIdentity, CacheKey, FileCache,
    analysis_options_fingerprint,
};
use radare3::loader::{GoblinLoader, LOADER_SEMANTICS_VERSION, Loader};
use radare3::search::{StringEncoding, extract_strings, find_bytes};
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
        Some("afl" | "analyze") => match args.next() {
            Some(path) => afl(&path, false),
            None => Err("afl requires a file path".to_string()),
        },
        Some("afl-seq" | "analyze-seq") => match args.next() {
            Some(path) => afl(&path, true),
            None => Err("afl-seq requires a file path".to_string()),
        },
        Some("afl-cache") => match args.next() {
            Some(path) => afl_cached(&path, args.next().as_deref()),
            None => Err("afl-cache requires a file path".to_string()),
        },
        Some("agf") => match args.next() {
            Some(path) => agf(&path, args.next().as_deref()),
            None => Err("agf requires a file path".to_string()),
        },
        Some("izz") => match args.next() {
            Some(path) => izz(&path, args.next().as_deref()),
            None => Err("izz requires a file path".to_string()),
        },
        Some("verify") => match args.next() {
            Some(path) => verify(&path),
            None => Err("verify requires a file path".to_string()),
        },
        Some("search" | "/x") => match (args.next(), args.next()) {
            (Some(path), Some(pattern)) => search_bytes(&path, &pattern),
            _ => Err("search requires a file path and hexadecimal pattern".to_string()),
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
        "radare3 {}\n\nUsage:\n  radare3 info <file>\n  radare3 decode <file> <address>\n  radare3 afl <file>\n  radare3 afl-seq <file>\n  radare3 afl-cache <file> [cache-dir]\n  radare3 agf <file> [function-address]\n  radare3 izz <file> [min-chars]\n  radare3 search <file> <hex-pattern>\n  radare3 /x <file> <hex-pattern>\n  radare3 verify <file>\n  radare3 --version",
        env!("CARGO_PKG_VERSION")
    );
}

fn load(path: &str) -> Result<radare3::image::BinaryImage, String> {
    let bytes =
        radare3::mmap::map_file(path).map_err(|error| format!("failed to map {path}: {error}"))?;
    GoblinLoader
        .load_data(bytes)
        .map_err(|error| error.to_string())
}

fn info(path: &str) -> Result<(), String> {
    let image = load(path)?;

    println!("format: {:?}", image.format);
    println!("architecture: {:?}", image.architecture);
    println!(
        "storage: {}",
        if image.is_mapped() { "mmap" } else { "owned" }
    );
    println!("base: {}", image.base_address);
    match image.entry_point {
        Some(entry) => println!("entry: {entry}"),
        None => println!("entry: none"),
    }
    println!("segments: {}", image.segments.len());
    println!("function-seeds: {}", image.function_seeds.len());

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
    ensure_x86_64(&image)?;

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

fn analyze_parallel(
    image: &radare3::image::BinaryImage,
) -> Result<radare3::analysis::AnalysisResult, String> {
    ParallelAnalyzer::new(IcedX86Decoder::x86_64())
        .analyze(image, &AnalysisOptions::default())
        .map_err(|error| format!("analysis failed: {error:?}"))
}

fn analyze_sequential(
    image: &radare3::image::BinaryImage,
) -> Result<radare3::analysis::AnalysisResult, String> {
    RecursiveAnalyzer::new(IcedX86Decoder::x86_64())
        .analyze(image, &AnalysisOptions::default())
        .map_err(|error| format!("analysis failed: {error:?}"))
}

fn afl(path: &str, sequential: bool) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;
    let result = if sequential {
        analyze_sequential(&image)?
    } else {
        analyze_parallel(&image)?
    };

    print_afl_result(&result, if sequential { "sequential" } else { "parallel" });

    Ok(())
}

fn afl_cached(path: &str, cache_dir: Option<&str>) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;

    let options = AnalysisOptions::default();
    let string_min_chars = 4;
    let fingerprint = analysis_options_fingerprint(&options, string_min_chars)
        .map_err(|error| format!("cache fingerprint failed: {error:?}"))?;
    let key = CacheKey::derive(&CacheIdentity::new(
        image.bytes(),
        LOADER_SEMANTICS_VERSION,
        DECODER_SEMANTICS_VERSION,
        &fingerprint,
    ));
    let cache = FileCache::new(cache_dir.unwrap_or(".radare3/cache"));

    let snapshot = match cache.get(key) {
        Ok(Some(payload)) => match AnalysisSnapshot::decode(&payload) {
            Ok(snapshot) => {
                eprintln!("cache=hit key={key}");
                snapshot
            }
            Err(CacheError::Corrupt | CacheError::IncompatibleVersion | CacheError::TooLarge) => {
                cache
                    .remove(key)
                    .map_err(|error| format!("failed to discard invalid cache entry: {error:?}"))?;
                build_cache_snapshot(&image, &options, string_min_chars, &cache, key)?
            }
            Err(CacheError::Io) => return Err("failed to decode cache payload".to_string()),
        },
        Ok(None) => build_cache_snapshot(&image, &options, string_min_chars, &cache, key)?,
        Err(CacheError::Corrupt | CacheError::IncompatibleVersion | CacheError::TooLarge) => {
            cache
                .remove(key)
                .map_err(|error| format!("failed to discard invalid cache entry: {error:?}"))?;
            build_cache_snapshot(&image, &options, string_min_chars, &cache, key)?
        }
        Err(CacheError::Io) => return Err("failed to read cache entry".to_string()),
    };

    print_afl_result(&snapshot.analysis, "cache");
    Ok(())
}

fn build_cache_snapshot(
    image: &radare3::image::BinaryImage,
    options: &AnalysisOptions,
    string_min_chars: usize,
    cache: &FileCache,
    key: CacheKey,
) -> Result<AnalysisSnapshot, String> {
    let analysis = ParallelAnalyzer::new(IcedX86Decoder::x86_64())
        .analyze(image, options)
        .map_err(|error| format!("analysis failed: {error:?}"))?;
    let strings = extract_strings(image, string_min_chars);
    let snapshot = AnalysisSnapshot::new(analysis, strings);
    let payload = snapshot
        .encode()
        .map_err(|error| format!("cache encoding failed: {error:?}"))?;
    cache
        .put(key, &payload)
        .map_err(|error| format!("cache write failed: {error:?}"))?;
    eprintln!("cache=miss key={key}");
    Ok(snapshot)
}

fn print_afl_result(result: &AnalysisResult, mode: &str) {
    for function in result.cfg.functions.values() {
        println!(
            "{} blocks={} {}",
            function.entry,
            function.blocks.len(),
            function.name.as_deref().unwrap_or("unnamed")
        );
    }

    eprintln!(
        "mode={} fidelity={:?} functions={} blocks={} xrefs={}",
        mode,
        result.fidelity,
        result.cfg.functions.len(),
        result.cfg.blocks.len(),
        result.xrefs.len()
    );
}

fn agf(path: &str, requested: Option<&str>) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;
    let result = analyze_parallel(&image)?;

    let address = match requested {
        Some(value) => parse_address(value)?,
        None => image
            .entry_point
            .ok_or_else(|| "binary has no entry point; pass a function address".to_string())?,
    };

    let function = result
        .cfg
        .functions
        .values()
        .find(|function| function.entry == address)
        .ok_or_else(|| format!("no discovered function at {address}"))?;

    println!(
        "{} {} blocks={}",
        function.entry,
        function.name.as_deref().unwrap_or("unnamed"),
        function.blocks.len()
    );

    for block_id in &function.blocks {
        let block = result
            .cfg
            .blocks
            .get(block_id)
            .ok_or_else(|| "CFG contains a missing block reference".to_string())?;

        let successors = block
            .successors
            .iter()
            .filter_map(|id| result.cfg.blocks.get(id))
            .map(|successor| successor.start.to_string())
            .collect::<Vec<_>>()
            .join(",");

        println!("  {}..{} -> [{}]", block.start, block.end, successors);
    }

    Ok(())
}

fn verify(path: &str) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;

    let sequential = analyze_sequential(&image)?;
    let parallel = analyze_parallel(&image)?;

    if sequential != parallel {
        return Err(format!(
            "parallel analysis diverged from sequential truth oracle: seq(f={},b={},x={}) par(f={},b={},x={})",
            sequential.cfg.functions.len(),
            sequential.cfg.blocks.len(),
            sequential.xrefs.len(),
            parallel.cfg.functions.len(),
            parallel.cfg.blocks.len(),
            parallel.xrefs.len()
        ));
    }

    println!(
        "verified functions={} blocks={} xrefs={} fidelity={:?}",
        parallel.cfg.functions.len(),
        parallel.cfg.blocks.len(),
        parallel.xrefs.len(),
        parallel.fidelity
    );

    Ok(())
}

fn izz(path: &str, minimum: Option<&str>) -> Result<(), String> {
    let image = load(path)?;
    let min_chars = minimum
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|error| format!("invalid minimum string length: {error}"))?
        .unwrap_or(4);

    for string in extract_strings(&image, min_chars) {
        let encoding = match string.encoding {
            StringEncoding::Ascii => "ascii",
            StringEncoding::Utf16Le => "utf16le",
        };
        println!("{} {} {}", string.address, encoding, string.value);
    }

    Ok(())
}

fn search_bytes(path: &str, pattern: &str) -> Result<(), String> {
    let image = load(path)?;
    let needle = parse_hex(pattern)?;

    if needle.is_empty() {
        return Err("hex pattern must not be empty".to_string());
    }

    let hits = find_bytes(&image, &needle);
    for hit in &hits {
        println!("{} len={}", hit.address, hit.length);
    }
    eprintln!("hits={}", hits.len());

    Ok(())
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '_')
        .collect();
    let compact = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact);

    if compact.is_empty() {
        return Ok(Vec::new());
    }
    if compact.len() % 2 != 0 {
        return Err("hex pattern must contain an even number of digits".to_string());
    }

    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|error| format!("invalid hex pattern: {error}"))?;
            u8::from_str_radix(text, 16)
                .map_err(|error| format!("invalid hex byte {text}: {error}"))
        })
        .collect()
}

fn ensure_x86_64(image: &radare3::image::BinaryImage) -> Result<(), String> {
    if image.architecture != Architecture::X86_64 {
        return Err(format!(
            "analysis currently supports x86-64 only, got {:?}",
            image.architecture
        ));
    }
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
