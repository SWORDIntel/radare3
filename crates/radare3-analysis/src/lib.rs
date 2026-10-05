#![forbid(unsafe_code)]

use radare3_cfg::ControlFlowGraph;
use radare3_image::BinaryImage;
use radare3_types::{Address, Fidelity};
use radare3_xref::Xref;

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
