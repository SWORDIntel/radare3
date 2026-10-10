use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use radare3::cfg::{BasicBlock, ControlFlowGraph, Function};
use radare3::image::{FunctionSeed, FunctionSeedKind, Import, ImportKind};
use radare3::types::{BinaryFormat, BlockId, Fidelity, FunctionId, XrefId};
use radare3::xref::{Xref, XrefKind};

#[test]
fn static_export_preserves_identity_and_canonical_graph() {
    let mut image = radare3::image::BinaryImage::new(
        Arc::<[u8]>::from(&b"abc"[..]),
        BinaryFormat::Pe,
        Architecture::X86_64,
        Address(0x0001_4000_0000),
        Some(Address(0x0001_4000_1000)),
        vec![],
    );
    image.imports.push(Import {
        slot: Some(Address(0x0001_4000_3000)),
        library: Some("ntoskrnl.exe".to_string()),
        name: "MmMapIoSpace".to_string(),
        ordinal: None,
        kind: ImportKind::Function,
    });
    image.function_seeds.push(FunctionSeed {
        address: Address(0x0001_4000_1000),
        kind: FunctionSeedKind::Symbol,
        name: Some("dispatch".to_string()),
    });
    let result = AnalysisResult {
        cfg: ControlFlowGraph {
            functions: BTreeMap::from([(
                FunctionId(0),
                Function {
                    id: FunctionId(0),
                    entry: Address(0x0001_4000_1000),
                    blocks: vec![BlockId(0)],
                    name: Some("dispatch".to_string()),
                },
            )]),
            blocks: BTreeMap::from([(
                BlockId(0),
                BasicBlock {
                    id: BlockId(0),
                    start: Address(0x0001_4000_1000),
                    end: Address(0x0001_4000_1010),
                    successors: vec![],
                },
            )]),
        },
        xrefs: vec![Xref {
            id: XrefId(0),
            from: Address(0x0001_4000_1004),
            to: Address(0x0001_4000_3000),
            kind: XrefKind::Call,
        }],
        fidelity: Fidelity::Incomplete,
    };

    let options = AnalysisOptions {
        entrypoints: vec![Address(0x0001_4000_1000)],
        max_instructions: Some(100),
        ..AnalysisOptions::default()
    };
    let export = static_export_json(&image, &result, &options);
    assert_eq!(export, static_export_json(&image, &result, &options));
    assert_eq!(export["schema"], "radare3.static.v1");
    assert_eq!(
        export["binary_sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(export["fidelity"], "incomplete");
    assert_eq!(export["analysis_options"]["max_instructions"], 100);
    assert_eq!(export["loader_semantics_version"], LOADER_SEMANTICS_VERSION);
    assert_eq!(
        export["decoder_semantics_version"],
        DECODER_SEMANTICS_VERSION
    );
    assert_eq!(export["functions"][0]["block_ids"][0], 0);
    assert_eq!(
        export["functions"][0]["seed_provenance"],
        serde_json::json!(["analysis_option_entrypoint", "image_entry", "symbol"])
    );
    assert_eq!(export["blocks"][0]["start"], 0x0001_4000_1000_u64);
    assert_eq!(export["xrefs"][0]["kind"], "call");
    assert_eq!(export["imports"][0]["name"], "MmMapIoSpace");
}
