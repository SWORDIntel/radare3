#![forbid(unsafe_code)]

use std::io::{self, Write};

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
use radare3::r2::{
    CommandDisposition, DefaultR2Compatibility, R2Compatibility, R2FallbackExecutor,
};
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
        Some("ij") => match args.next() {
            Some(path) => info_json(&path),
            None => Err("ij requires a file path".to_string()),
        },
        Some("iS") => match args.next() {
            Some(path) => sections(&path, false),
            None => Err("iS requires a file path".to_string()),
        },
        Some("iSj") => match args.next() {
            Some(path) => sections(&path, true),
            None => Err("iSj requires a file path".to_string()),
        },
        Some("decode") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => decode(&path, &address),
            _ => Err("decode requires a file path and virtual address".to_string()),
        },
        Some("afl" | "analyze") => match args.next() {
            Some(path) => afl(&path, false),
            None => Err("afl requires a file path".to_string()),
        },
        Some("aflj") => match args.next() {
            Some(path) => afl_json(&path),
            None => Err("aflj requires a file path".to_string()),
        },
        Some("afi") => match args.next() {
            Some(path) => afi(&path, args.next().as_deref()),
            None => Err("afi requires a file path".to_string()),
        },
        Some("afij") => match args.next() {
            Some(path) => afi_json(&path, args.next().as_deref()),
            None => Err("afij requires a file path".to_string()),
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
        Some("agfj") => match args.next() {
            Some(path) => agf_json(&path, args.next().as_deref()),
            None => Err("agfj requires a file path".to_string()),
        },
        Some("axt") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => xrefs_to(&path, &address, false),
            _ => Err("axt requires a file path and address".to_string()),
        },
        Some("axtj") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => xrefs_to(&path, &address, true),
            _ => Err("axtj requires a file path and address".to_string()),
        },
        Some("axf") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => xrefs_from(&path, &address, false),
            _ => Err("axf requires a file path and address".to_string()),
        },
        Some("axfj") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => xrefs_from(&path, &address, true),
            _ => Err("axfj requires a file path and address".to_string()),
        },
        Some("izz") => match args.next() {
            Some(path) => izz(&path, args.next().as_deref()),
            None => Err("izz requires a file path".to_string()),
        },
        Some("izzj") => match args.next() {
            Some(path) => izz_json(&path, args.next().as_deref()),
            None => Err("izzj requires a file path".to_string()),
        },
        Some("verify") => match args.next() {
            Some(path) => verify(&path),
            None => Err("verify requires a file path".to_string()),
        },
        Some("search" | "/x") => match (args.next(), args.next()) {
            (Some(path), Some(pattern)) => search_bytes(&path, &pattern),
            _ => Err("search requires a file path and hexadecimal pattern".to_string()),
        },
        Some("/xj") => match (args.next(), args.next()) {
            (Some(path), Some(pattern)) => search_bytes_json(&path, &pattern),
            _ => Err("/xj requires a file path and hexadecimal pattern".to_string()),
        },
        Some("px") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => hexdump(&path, &address, args.next().as_deref(), false),
            _ => Err("px requires a file path and address".to_string()),
        },
        Some("pxj") => match (args.next(), args.next()) {
            (Some(path), Some(address)) => hexdump(&path, &address, args.next().as_deref(), true),
            _ => Err("pxj requires a file path and address".to_string()),
        },
        Some("route") => match args.next() {
            Some(path) => {
                let command = args.collect::<Vec<_>>().join(" ");
                route_command(&path, &command)
            }
            None => Err("route requires a file path and command".to_string()),
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
        "radare3 {}\n\nUsage:\n  radare3 info <file>\n  radare3 ij <file>\n  radare3 iS <file>\n  radare3 iSj <file>\n  radare3 decode <file> <address>\n  radare3 afl <file>\n  radare3 aflj <file>\n  radare3 afi <file> [function-address]\n  radare3 afij <file> [function-address]\n  radare3 afl-seq <file>\n  radare3 afl-cache <file> [cache-dir]\n  radare3 agf <file> [function-address]\n  radare3 agfj <file> [function-address]\n  radare3 axt <file> <address>\n  radare3 axtj <file> <address>\n  radare3 axf <file> <address>\n  radare3 axfj <file> <address>\n  radare3 izz <file> [min-chars]\n  radare3 izzj <file> [min-chars]\n  radare3 search <file> <hex-pattern>\n  radare3 /x <file> <hex-pattern>\n  radare3 /xj <file> <hex-pattern>\n  radare3 px <file> <address> [length]\n  radare3 pxj <file> <address> [length]\n  radare3 route <file> <r2-style-command...>\n  radare3 verify <file>\n  radare3 --version",
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

fn info_json(path: &str) -> Result<(), String> {
    let image = load(path)?;
    let segments = image
        .segments
        .iter()
        .map(|segment| {
            serde_json::json!({
                "name": segment.name,
                "address": segment.address.0,
                "file_offset": segment.file_offset,
                "file_size": segment.file_size,
                "memory_size": segment.memory_size,
                "permissions": {
                    "read": segment.permissions.read,
                    "write": segment.permissions.write,
                    "execute": segment.permissions.execute,
                }
            })
        })
        .collect::<Vec<_>>();

    print_json(serde_json::json!({
        "schema": "radare3.info.v1",
        "format": format_name(image.format),
        "architecture": architecture_name(image.architecture),
        "storage": if image.is_mapped() { "mmap" } else { "owned" },
        "base_address": image.base_address.0,
        "entry_point": image.entry_point.map(|address| address.0),
        "function_seed_count": image.function_seeds.len(),
        "segments": segments,
    }))
}

fn sections(path: &str, json: bool) -> Result<(), String> {
    let image = load(path)?;

    if json {
        let segments = image
            .segments
            .iter()
            .map(|segment| {
                serde_json::json!({
                    "name": segment.name,
                    "address": segment.address.0,
                    "file_offset": segment.file_offset,
                    "file_size": segment.file_size,
                    "memory_size": segment.memory_size,
                    "permissions": {
                        "read": segment.permissions.read,
                        "write": segment.permissions.write,
                        "execute": segment.permissions.execute,
                    }
                })
            })
            .collect::<Vec<_>>();

        return print_json(serde_json::json!({
            "schema": "radare3.sections.v1",
            "segments": segments,
        }));
    }

    for segment in &image.segments {
        println!(
            "{} {} file=0x{:x}+0x{:x} mem=0x{:x} r{}w{}x{}",
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
    let options = analysis_options_from_env()?;
    analyze_parallel_with_options(image, &options)
}

fn analyze_parallel_with_options(
    image: &radare3::image::BinaryImage,
    options: &AnalysisOptions,
) -> Result<radare3::analysis::AnalysisResult, String> {
    ParallelAnalyzer::new(IcedX86Decoder::x86_64())
        .analyze(image, options)
        .map_err(|error| format!("analysis failed: {error:?}"))
}

fn analyze_sequential(
    image: &radare3::image::BinaryImage,
) -> Result<radare3::analysis::AnalysisResult, String> {
    let options = analysis_options_from_env()?;
    RecursiveAnalyzer::new(IcedX86Decoder::x86_64())
        .analyze(image, &options)
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

fn afl_json(path: &str) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;
    let result = analyze_parallel(&image)?;

    let functions = result
        .cfg
        .functions
        .values()
        .map(|function| {
            serde_json::json!({
                "id": function.id.0,
                "entry": function.entry.0,
                "name": function.name,
                "block_ids": function.blocks.iter().map(|id| id.0).collect::<Vec<_>>(),
                "block_count": function.blocks.len(),
            })
        })
        .collect::<Vec<_>>();

    print_json(serde_json::json!({
        "schema": "radare3.afl.v1",
        "fidelity": fidelity_name(result.fidelity),
        "functions": functions,
    }))
}

fn afi(path: &str, requested: Option<&str>) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;
    let result = analyze_parallel(&image)?;
    let function = resolve_function(&image, &result, requested)?;
    let (incoming, outgoing) = function_xref_counts(&result, function);

    println!(
        "{} {} blocks={} xrefs_in={} xrefs_out={}",
        function.entry,
        function.name.as_deref().unwrap_or("unnamed"),
        function.blocks.len(),
        incoming,
        outgoing
    );

    Ok(())
}

fn afi_json(path: &str, requested: Option<&str>) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;
    let result = analyze_parallel(&image)?;
    let function = resolve_function(&image, &result, requested)?;
    let (incoming, outgoing) = function_xref_counts(&result, function);

    print_json(serde_json::json!({
        "schema": "radare3.afi.v1",
        "function": {
            "id": function.id.0,
            "entry": function.entry.0,
            "name": function.name,
            "block_ids": function.blocks.iter().map(|id| id.0).collect::<Vec<_>>(),
            "block_count": function.blocks.len(),
            "xrefs_in": incoming,
            "xrefs_out": outgoing,
        }
    }))
}

fn afl_cached(path: &str, cache_dir: Option<&str>) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;

    let options = analysis_options_from_env()?;
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
    let analysis = analyze_parallel_with_options(image, options)?;
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

fn agf_json(path: &str, requested: Option<&str>) -> Result<(), String> {
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

    let blocks = function
        .blocks
        .iter()
        .map(|block_id| {
            let block = result
                .cfg
                .blocks
                .get(block_id)
                .ok_or_else(|| "CFG contains a missing block reference".to_string())?;
            Ok(serde_json::json!({
                "id": block.id.0,
                "start": block.start.0,
                "end": block.end.0,
                "successors": block.successors.iter().map(|id| id.0).collect::<Vec<_>>(),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    print_json(serde_json::json!({
        "schema": "radare3.agf.v1",
        "function": {
            "id": function.id.0,
            "entry": function.entry.0,
            "name": function.name,
            "blocks": blocks,
        }
    }))
}

fn xrefs_to(path: &str, requested: &str, json: bool) -> Result<(), String> {
    query_xrefs(path, requested, true, json)
}

fn xrefs_from(path: &str, requested: &str, json: bool) -> Result<(), String> {
    query_xrefs(path, requested, false, json)
}

fn query_xrefs(path: &str, requested: &str, incoming: bool, json: bool) -> Result<(), String> {
    let image = load(path)?;
    ensure_x86_64(&image)?;
    let result = analyze_parallel(&image)?;
    let address = parse_address(requested)?;

    let matches = result
        .xrefs
        .iter()
        .filter(|xref| {
            if incoming {
                xref.to == address
            } else {
                xref.from == address
            }
        })
        .collect::<Vec<_>>();

    if json {
        let refs = matches
            .iter()
            .map(|xref| {
                serde_json::json!({
                    "id": xref.id.0,
                    "from": xref.from.0,
                    "to": xref.to.0,
                    "kind": xref_kind_name(xref.kind),
                })
            })
            .collect::<Vec<_>>();
        let schema = if incoming {
            "radare3.axt.v1"
        } else {
            "radare3.axf.v1"
        };
        return print_json(serde_json::json!({
            "schema": schema,
            "address": address.0,
            "xrefs": refs,
        }));
    }

    for xref in matches {
        println!("{} {} -> {}", xref_kind_name(xref.kind), xref.from, xref.to);
    }

    Ok(())
}

fn resolve_function<'a>(
    image: &radare3::image::BinaryImage,
    result: &'a AnalysisResult,
    requested: Option<&str>,
) -> Result<&'a radare3::cfg::Function, String> {
    let address = match requested {
        Some(value) => parse_address(value)?,
        None => image
            .entry_point
            .ok_or_else(|| "binary has no entry point; pass a function address".to_string())?,
    };

    result
        .cfg
        .functions
        .values()
        .find(|function| function.entry == address)
        .ok_or_else(|| format!("no discovered function at {address}"))
}

fn function_xref_counts(
    result: &AnalysisResult,
    function: &radare3::cfg::Function,
) -> (usize, usize) {
    let incoming = result
        .xrefs
        .iter()
        .filter(|xref| xref.to == function.entry)
        .count();

    let outgoing = result
        .xrefs
        .iter()
        .filter(|xref| function_contains_address(result, function, xref.from))
        .count();

    (incoming, outgoing)
}

fn function_contains_address(
    result: &AnalysisResult,
    function: &radare3::cfg::Function,
    address: Address,
) -> bool {
    function.blocks.iter().any(|block_id| {
        result
            .cfg
            .blocks
            .get(block_id)
            .is_some_and(|block| address >= block.start && address < block.end)
    })
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
    let min_chars = parse_minimum_string_length(minimum)?;

    for string in extract_strings(&image, min_chars) {
        let encoding = match string.encoding {
            StringEncoding::Ascii => "ascii",
            StringEncoding::Utf16Le => "utf16le",
        };
        println!("{} {} {}", string.address, encoding, string.value);
    }

    Ok(())
}

fn izz_json(path: &str, minimum: Option<&str>) -> Result<(), String> {
    let image = load(path)?;
    let min_chars = parse_minimum_string_length(minimum)?;
    let strings = extract_strings(&image, min_chars)
        .into_iter()
        .map(|string| {
            serde_json::json!({
                "address": string.address.0,
                "encoding": string_encoding_name(string.encoding),
                "value": string.value,
            })
        })
        .collect::<Vec<_>>();

    print_json(serde_json::json!({
        "schema": "radare3.izz.v1",
        "minimum_characters": min_chars,
        "strings": strings,
    }))
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

fn search_bytes_json(path: &str, pattern: &str) -> Result<(), String> {
    let image = load(path)?;
    let needle = parse_hex(pattern)?;

    if needle.is_empty() {
        return Err("hex pattern must not be empty".to_string());
    }

    let hits = find_bytes(&image, &needle)
        .into_iter()
        .map(|hit| {
            serde_json::json!({
                "address": hit.address.0,
                "length": hit.length,
            })
        })
        .collect::<Vec<_>>();

    print_json(serde_json::json!({
        "schema": "radare3.search.v1",
        "pattern_hex": hex_bytes(&needle),
        "hits": hits,
    }))
}

fn parse_minimum_string_length(minimum: Option<&str>) -> Result<usize, String> {
    minimum
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|error| format!("invalid minimum string length: {error}"))
        .map(|value| value.unwrap_or(4))
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let output = serde_json::to_string(&value)
        .map_err(|error| format!("JSON serialization failed: {error}"))?;
    println!("{output}");
    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn format_name(format: radare3::types::BinaryFormat) -> &'static str {
    match format {
        radare3::types::BinaryFormat::Elf => "elf",
        radare3::types::BinaryFormat::Pe => "pe",
        radare3::types::BinaryFormat::MachO => "macho",
        radare3::types::BinaryFormat::Raw => "raw",
        radare3::types::BinaryFormat::Unknown => "unknown",
    }
}

const fn architecture_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86 => "x86",
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "arm64",
        Architecture::Unknown => "unknown",
    }
}

const fn fidelity_name(fidelity: radare3::types::Fidelity) -> &'static str {
    match fidelity {
        radare3::types::Fidelity::Canonical => "canonical",
        radare3::types::Fidelity::Heuristic => "heuristic",
        radare3::types::Fidelity::Incomplete => "incomplete",
    }
}

const fn xref_kind_name(kind: radare3::xref::XrefKind) -> &'static str {
    match kind {
        radare3::xref::XrefKind::Call => "call",
        radare3::xref::XrefKind::Code => "code",
        radare3::xref::XrefKind::Data => "data",
    }
}

const fn string_encoding_name(encoding: StringEncoding) -> &'static str {
    match encoding {
        StringEncoding::Ascii => "ascii",
        StringEncoding::Utf16Le => "utf16le",
    }
}

fn hexdump(path: &str, requested: &str, length: Option<&str>, json: bool) -> Result<(), String> {
    let image = load(path)?;
    let address = parse_address(requested)?;
    let length = parse_length(length)?;
    let bytes = image
        .bytes_at(address, length)
        .ok_or_else(|| format!("address {address} is not file-backed"))?;

    if json {
        return print_json(serde_json::json!({
            "schema": "radare3.px.v1",
            "address": address.0,
            "requested_length": length,
            "length": bytes.len(),
            "bytes_hex": hex_bytes(bytes),
        }));
    }

    for (line, chunk) in bytes.chunks(16).enumerate() {
        let offset = u64::try_from(line)
            .ok()
            .and_then(|line| line.checked_mul(16))
            .ok_or_else(|| "hex dump address overflow".to_string())?;
        let line_address = address
            .0
            .checked_add(offset)
            .ok_or_else(|| "hex dump address overflow".to_string())?;
        let hex = chunk
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii = chunk
            .iter()
            .map(|byte| {
                if matches!(*byte, 0x20..=0x7e) {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect::<String>();
        println!("0x{line_address:016x}  {hex:<47}  {ascii}");
    }

    Ok(())
}

fn parse_length(value: Option<&str>) -> Result<usize, String> {
    let value = match value {
        Some(value) => parse_address(value)?.0,
        None => 64,
    };
    usize::try_from(value).map_err(|_| "length does not fit this platform".to_string())
}

fn route_command(path: &str, command: &str) -> Result<(), String> {
    if command.trim().is_empty() {
        return Err("route requires a non-empty command".to_string());
    }

    match DefaultR2Compatibility.classify_command(command) {
        CommandDisposition::Native => route_native(path, command),
        CommandDisposition::Fallback => route_fallback(path, command),
        CommandDisposition::Unsupported => Err(format!("unsupported routed command: {command}")),
    }
}

fn route_native(path: &str, command: &str) -> Result<(), String> {
    let mut parts = command.split_ascii_whitespace();
    let head = parts
        .next()
        .ok_or_else(|| "route requires a non-empty command".to_string())?;

    match head {
        "afl" => require_no_extra(parts, "afl").and_then(|()| afl(path, false)),
        "aflj" => require_no_extra(parts, "aflj").and_then(|()| afl_json(path)),
        "afi" => route_optional_function_info(path, parts, false),
        "afij" => route_optional_function_info(path, parts, true),
        "agf" => route_optional_address(path, parts, false),
        "agfj" => route_optional_address(path, parts, true),
        "axt" => route_required_xref_address(path, parts, true, false),
        "axtj" => route_required_xref_address(path, parts, true, true),
        "axf" => route_required_xref_address(path, parts, false, false),
        "axfj" => route_required_xref_address(path, parts, false, true),
        "izz" => route_optional_minimum(path, parts, false),
        "izzj" => route_optional_minimum(path, parts, true),
        "/x" => route_pattern(path, parts, false),
        "/xj" => route_pattern(path, parts, true),
        "ij" => require_no_extra(parts, "ij").and_then(|()| info_json(path)),
        "iS" => require_no_extra(parts, "iS").and_then(|()| sections(path, false)),
        "iSj" => require_no_extra(parts, "iSj").and_then(|()| sections(path, true)),
        _ => Err(format!("native route missing implementation for {head}")),
    }
}

fn route_fallback(path: &str, command: &str) -> Result<(), String> {
    eprintln!("route=fallback engine=radare2 command={command}");

    let output = R2FallbackExecutor::default()
        .execute(path, command)
        .map_err(|error| format!("radare2 fallback failed: {error:?}"))?;

    {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        handle
            .write_all(&output.stdout)
            .map_err(|error| format!("failed to forward radare2 stdout: {error}"))?;
        handle
            .flush()
            .map_err(|error| format!("failed to flush radare2 stdout: {error}"))?;
    }

    {
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        handle
            .write_all(&output.stderr)
            .map_err(|error| format!("failed to forward radare2 stderr: {error}"))?;
        handle
            .flush()
            .map_err(|error| format!("failed to flush radare2 stderr: {error}"))?;
    }

    if output.timed_out {
        return Err("radare2 fallback timed out".to_string());
    }

    if output.exit_code != Some(0) {
        return Err(format!(
            "radare2 fallback exited with status {:?}",
            output.exit_code
        ));
    }

    Ok(())
}

fn require_no_extra<'a>(
    mut parts: impl Iterator<Item = &'a str>,
    command: &str,
) -> Result<(), String> {
    if parts.next().is_some() {
        return Err(format!("{command} does not accept routed arguments"));
    }
    Ok(())
}

fn route_optional_function_info<'a>(
    path: &str,
    mut parts: impl Iterator<Item = &'a str>,
    json: bool,
) -> Result<(), String> {
    let address = parts.next();
    if parts.next().is_some() {
        return Err("afi/afij accept at most one function address".to_string());
    }

    if json {
        afi_json(path, address)
    } else {
        afi(path, address)
    }
}

fn route_required_xref_address<'a>(
    path: &str,
    mut parts: impl Iterator<Item = &'a str>,
    incoming: bool,
    json: bool,
) -> Result<(), String> {
    let address = parts
        .next()
        .ok_or_else(|| "xref commands require an address".to_string())?;
    if parts.next().is_some() {
        return Err("xref commands accept exactly one address".to_string());
    }

    if incoming {
        xrefs_to(path, address, json)
    } else {
        xrefs_from(path, address, json)
    }
}

fn route_optional_address<'a>(
    path: &str,
    mut parts: impl Iterator<Item = &'a str>,
    json: bool,
) -> Result<(), String> {
    let address = parts.next();
    if parts.next().is_some() {
        return Err("agf/agfj accept at most one function address".to_string());
    }

    if json {
        agf_json(path, address)
    } else {
        agf(path, address)
    }
}

fn route_optional_minimum<'a>(
    path: &str,
    mut parts: impl Iterator<Item = &'a str>,
    json: bool,
) -> Result<(), String> {
    let minimum = parts.next();
    if parts.next().is_some() {
        return Err("izz/izzj accept at most one minimum length".to_string());
    }

    if json {
        izz_json(path, minimum)
    } else {
        izz(path, minimum)
    }
}

fn route_pattern<'a>(
    path: &str,
    parts: impl Iterator<Item = &'a str>,
    json: bool,
) -> Result<(), String> {
    let pattern = parts.collect::<String>();
    if pattern.is_empty() {
        return Err("/x and /xj require a hexadecimal pattern".to_string());
    }

    if json {
        search_bytes_json(path, &pattern)
    } else {
        search_bytes(path, &pattern)
    }
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

fn analysis_options_from_env() -> Result<AnalysisOptions, String> {
    Ok(AnalysisOptions {
        max_instructions: env_limit("RADARE3_MAX_INSTRUCTIONS")?,
        max_functions: env_limit("RADARE3_MAX_FUNCTIONS")?,
        max_blocks: env_limit("RADARE3_MAX_BLOCKS")?,
        max_xrefs: env_limit("RADARE3_MAX_XREFS")?,
        ..AnalysisOptions::default()
    })
}

fn env_limit(name: &str) -> Result<Option<u64>, String> {
    match std::env::var(name) {
        Ok(value) => {
            let value = value
                .parse::<u64>()
                .map_err(|error| format!("invalid {name}={value:?}: {error}"))?;
            Ok(Some(value))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{name} contains non-Unicode data"))
        }
    }
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
