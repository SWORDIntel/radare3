#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use radare3_cfg::{ControlFlowGraph, Function};
use radare3_types::FunctionId;
use radare3_xref::{Xref, XrefKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportError {
    MissingBlock,
    InvalidBlockRange,
}

pub fn export_analysis_script(
    cfg: &ControlFlowGraph,
    xrefs: &[Xref],
) -> Result<String, ExportError> {
    let names = export_function_names(cfg);
    let mut output = String::new();

    for function in cfg.functions.values() {
        let name = names
            .get(&function.id)
            .map(String::as_str)
            .unwrap_or("r3_function");
        output.push_str(&format!("af+ 0x{:x} {name}\n", function.entry.0));

        for block_id in &function.blocks {
            let block = cfg.blocks.get(block_id).ok_or(ExportError::MissingBlock)?;
            let size = block
                .end
                .0
                .checked_sub(block.start.0)
                .ok_or(ExportError::InvalidBlockRange)?;
            if size == 0 {
                return Err(ExportError::InvalidBlockRange);
            }
            output.push_str(&format!(
                "afb+ 0x{:x} 0x{:x} 0x{size:x}\n",
                function.entry.0, block.start.0
            ));
        }
    }

    for xref in xrefs {
        let command = match xref.kind {
            XrefKind::Call => "axC",
            XrefKind::Code => "axc",
            XrefKind::Data => "axd",
        };
        output.push_str(&format!(
            "{command} 0x{:x} 0x{:x}\n",
            xref.to.0, xref.from.0
        ));
    }

    Ok(output)
}

fn export_function_names(cfg: &ControlFlowGraph) -> BTreeMap<FunctionId, String> {
    let mut used = BTreeSet::new();
    let mut names = BTreeMap::new();

    for function in cfg.functions.values() {
        let base = export_function_name(function);
        let mut candidate = base.clone();

        if !used.insert(candidate.clone()) {
            candidate = format!("{base}_r3_{:x}", function.entry.0);
            used.insert(candidate.clone());
        }

        names.insert(function.id, candidate);
    }

    names
}

fn export_function_name(function: &Function) -> String {
    let raw = function
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("sub_{:x}", function.entry.0));

    let mut sanitized = String::with_capacity(raw.len());
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':') {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }

    if sanitized.is_empty() {
        format!("sub_{:x}", function.entry.0)
    } else {
        sanitized
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDisposition {
    Native,
    Fallback,
    Unsupported,
}

pub trait R2Compatibility: Send + Sync {
    fn classify_command(&self, command: &str) -> CommandDisposition;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultR2Compatibility;

impl R2Compatibility for DefaultR2Compatibility {
    fn classify_command(&self, command: &str) -> CommandDisposition {
        let Some(head) = command.split_ascii_whitespace().next() else {
            return CommandDisposition::Unsupported;
        };

        match head {
            "afl" | "afi" | "afij" | "agf" | "izz" | "/x" | "/xj" | "aflj" | "agfj" | "izzj"
            | "ij" | "iS" | "iSj" | "is" | "isj" | "ii" | "iij" | "axt" | "axtj" | "axf"
            | "axfj" | "pdf" | "pdfj" => CommandDisposition::Native,
            "aaa" | "px" | "pxj" | "s" => CommandDisposition::Fallback,
            _ => CommandDisposition::Unsupported,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FallbackError {
    NotFallback(CommandDisposition),
    Spawn,
    Io,
    Join,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

#[derive(Clone, Debug)]
pub struct R2FallbackExecutor {
    executable: PathBuf,
    timeout: Duration,
}

impl Default for R2FallbackExecutor {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("r2"),
            timeout: Duration::from_secs(30),
        }
    }
}

impl R2FallbackExecutor {
    pub fn new(executable: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            executable: executable.into(),
            timeout,
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn execute(
        &self,
        binary: impl AsRef<Path>,
        command: &str,
    ) -> Result<FallbackOutput, FallbackError> {
        let disposition = DefaultR2Compatibility.classify_command(command);
        if disposition != CommandDisposition::Fallback {
            return Err(FallbackError::NotFallback(disposition));
        }

        let mut child = Command::new(&self.executable)
            .arg("-2")
            .arg("-q")
            .arg("-c")
            .arg(command)
            .arg(binary.as_ref())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| FallbackError::Spawn)?;

        let stdout = child.stdout.take().ok_or(FallbackError::Io)?;
        let stderr = child.stderr.take().ok_or(FallbackError::Io)?;

        let stdout_thread = thread::spawn(move || read_all(stdout));
        let stderr_thread = thread::spawn(move || read_all(stderr));

        let start = Instant::now();
        let mut timed_out = false;

        let status = loop {
            match child.try_wait().map_err(|_| FallbackError::Io)? {
                Some(status) => break status,
                None if start.elapsed() >= self.timeout => {
                    timed_out = true;
                    child.kill().map_err(|_| FallbackError::Io)?;
                    break child.wait().map_err(|_| FallbackError::Io)?;
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        };

        let stdout = stdout_thread
            .join()
            .map_err(|_| FallbackError::Join)?
            .map_err(|_| FallbackError::Io)?;
        let stderr = stderr_thread
            .join()
            .map_err(|_| FallbackError::Join)?
            .map_err(|_| FallbackError::Io)?;

        Ok(FallbackOutput {
            exit_code: status.code(),
            stdout,
            stderr,
            timed_out,
        })
    }
}

fn read_all(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export_cfg() -> ControlFlowGraph {
        use radare3_cfg::{BasicBlock, Function};
        use radare3_types::{Address, BlockId, FunctionId};

        ControlFlowGraph {
            functions: BTreeMap::from([
                (
                    FunctionId(0),
                    Function {
                        id: FunctionId(0),
                        entry: Address(0x1000),
                        blocks: vec![BlockId(0)],
                        name: Some("main function".to_string()),
                    },
                ),
                (
                    FunctionId(1),
                    Function {
                        id: FunctionId(1),
                        entry: Address(0x2000),
                        blocks: vec![BlockId(1)],
                        name: Some("main function".to_string()),
                    },
                ),
            ]),
            blocks: BTreeMap::from([
                (
                    BlockId(0),
                    BasicBlock {
                        id: BlockId(0),
                        start: Address(0x1000),
                        end: Address(0x1010),
                        successors: Vec::new(),
                    },
                ),
                (
                    BlockId(1),
                    BasicBlock {
                        id: BlockId(1),
                        start: Address(0x2000),
                        end: Address(0x2008),
                        successors: Vec::new(),
                    },
                ),
            ]),
        }
    }

    #[test]
    fn exports_deterministic_additive_r2_script() -> Result<(), ExportError> {
        use radare3_types::{Address, XrefId};

        let cfg = export_cfg();
        let xrefs = vec![
            Xref {
                id: XrefId(0),
                from: Address(0x1004),
                to: Address(0x2000),
                kind: XrefKind::Call,
            },
            Xref {
                id: XrefId(1),
                from: Address(0x1008),
                to: Address(0x3000),
                kind: XrefKind::Code,
            },
            Xref {
                id: XrefId(2),
                from: Address(0x100c),
                to: Address(0x4000),
                kind: XrefKind::Data,
            },
        ];

        let script = export_analysis_script(&cfg, &xrefs)?;
        assert_eq!(
            script,
            concat!(
                "af+ 0x1000 main_function\n",
                "afb+ 0x1000 0x1000 0x10\n",
                "af+ 0x2000 main_function_r3_2000\n",
                "afb+ 0x2000 0x2000 0x8\n",
                "axC 0x2000 0x1004\n",
                "axc 0x3000 0x1008\n",
                "axd 0x4000 0x100c\n",
            )
        );

        Ok(())
    }

    #[test]
    fn export_rejects_missing_block() -> Result<(), ExportError> {
        use radare3_types::{BlockId, FunctionId};

        let mut cfg = export_cfg();
        let function = cfg
            .functions
            .get_mut(&FunctionId(0))
            .ok_or(ExportError::MissingBlock)?;
        function.blocks = vec![BlockId(99)];

        assert_eq!(
            export_analysis_script(&cfg, &[]),
            Err(ExportError::MissingBlock)
        );
        Ok(())
    }

    #[test]
    fn export_rejects_invalid_block_range() -> Result<(), ExportError> {
        use radare3_types::{Address, BlockId};

        let mut cfg = export_cfg();
        let block = cfg
            .blocks
            .get_mut(&BlockId(0))
            .ok_or(ExportError::MissingBlock)?;
        block.start = Address(0x1010);
        block.end = Address(0x1000);

        assert_eq!(
            export_analysis_script(&cfg, &[]),
            Err(ExportError::InvalidBlockRange)
        );
        Ok(())
    }

    #[test]
    fn classifies_native_commands() {
        let router = DefaultR2Compatibility;

        for command in [
            "afl",
            "afi",
            "afij",
            "agf",
            "izz",
            "/x",
            "/x 7f454c46",
            "/xj",
            "aflj",
            "agfj",
            "izzj",
            "ij",
            "iS",
            "iSj",
            "is",
            "isj",
            "ii",
            "iij",
            "axt",
            "axtj",
            "axf",
            "axfj",
            "pdf",
            "pdfj",
        ] {
            assert_eq!(
                router.classify_command(command),
                CommandDisposition::Native,
                "{command}"
            );
        }
    }

    #[test]
    fn classifies_known_fallback_commands() {
        let router = DefaultR2Compatibility;

        for command in ["aaa", "px 64", "pxj 64", "s 0x401000"] {
            assert_eq!(
                router.classify_command(command),
                CommandDisposition::Fallback,
                "{command}"
            );
        }
    }

    #[test]
    fn unknown_and_empty_commands_are_unsupported() {
        let router = DefaultR2Compatibility;

        for command in ["", "   ", "does-not-exist"] {
            assert_eq!(
                router.classify_command(command),
                CommandDisposition::Unsupported,
                "{command}"
            );
        }
    }

    #[test]
    fn executor_refuses_native_and_unknown_commands_without_spawning() {
        let executor = R2FallbackExecutor::new(
            "definitely-not-a-real-radare2-binary",
            Duration::from_millis(1),
        );

        assert_eq!(
            executor.execute("sample.bin", "afl"),
            Err(FallbackError::NotFallback(CommandDisposition::Native))
        );
        assert_eq!(
            executor.execute("sample.bin", "unknown-command"),
            Err(FallbackError::NotFallback(CommandDisposition::Unsupported))
        );
    }

    #[test]
    fn fallback_spawn_failure_is_explicit() {
        let executor = R2FallbackExecutor::new(
            "definitely-not-a-real-radare2-binary",
            Duration::from_millis(1),
        );

        assert_eq!(
            executor.execute("sample.bin", "aaa"),
            Err(FallbackError::Spawn)
        );
    }
}
) {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }

    if sanitized.is_empty() {
        format!("sub_{:x}", function.entry.0)
    } else {
        sanitized
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDisposition {
    Native,
    Fallback,
    Unsupported,
}

pub trait R2Compatibility: Send + Sync {
    fn classify_command(&self, command: &str) -> CommandDisposition;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultR2Compatibility;

impl R2Compatibility for DefaultR2Compatibility {
    fn classify_command(&self, command: &str) -> CommandDisposition {
        let Some(head) = command.split_ascii_whitespace().next() else {
            return CommandDisposition::Unsupported;
        };

        match head {
            "afl" | "afi" | "afij" | "agf" | "izz" | "/x" | "/xj" | "aflj" | "agfj" | "izzj"
            | "ij" | "iS" | "iSj" | "is" | "isj" | "ii" | "iij" | "axt" | "axtj" | "axf"
            | "axfj" | "pdf" | "pdfj" => CommandDisposition::Native,
            "aaa" | "px" | "pxj" | "s" => CommandDisposition::Fallback,
            _ => CommandDisposition::Unsupported,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FallbackError {
    NotFallback(CommandDisposition),
    Spawn,
    Io,
    Join,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

#[derive(Clone, Debug)]
pub struct R2FallbackExecutor {
    executable: PathBuf,
    timeout: Duration,
}

impl Default for R2FallbackExecutor {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("r2"),
            timeout: Duration::from_secs(30),
        }
    }
}

impl R2FallbackExecutor {
    pub fn new(executable: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            executable: executable.into(),
            timeout,
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn execute(
        &self,
        binary: impl AsRef<Path>,
        command: &str,
    ) -> Result<FallbackOutput, FallbackError> {
        let disposition = DefaultR2Compatibility.classify_command(command);
        if disposition != CommandDisposition::Fallback {
            return Err(FallbackError::NotFallback(disposition));
        }

        let mut child = Command::new(&self.executable)
            .arg("-2")
            .arg("-q")
            .arg("-c")
            .arg(command)
            .arg(binary.as_ref())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| FallbackError::Spawn)?;

        let stdout = child.stdout.take().ok_or(FallbackError::Io)?;
        let stderr = child.stderr.take().ok_or(FallbackError::Io)?;

        let stdout_thread = thread::spawn(move || read_all(stdout));
        let stderr_thread = thread::spawn(move || read_all(stderr));

        let start = Instant::now();
        let mut timed_out = false;

        let status = loop {
            match child.try_wait().map_err(|_| FallbackError::Io)? {
                Some(status) => break status,
                None if start.elapsed() >= self.timeout => {
                    timed_out = true;
                    child.kill().map_err(|_| FallbackError::Io)?;
                    break child.wait().map_err(|_| FallbackError::Io)?;
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        };

        let stdout = stdout_thread
            .join()
            .map_err(|_| FallbackError::Join)?
            .map_err(|_| FallbackError::Io)?;
        let stderr = stderr_thread
            .join()
            .map_err(|_| FallbackError::Join)?
            .map_err(|_| FallbackError::Io)?;

        Ok(FallbackOutput {
            exit_code: status.code(),
            stdout,
            stderr,
            timed_out,
        })
    }
}

fn read_all(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_native_commands() {
        let router = DefaultR2Compatibility;

        for command in [
            "afl",
            "afi",
            "afij",
            "agf",
            "izz",
            "/x",
            "/x 7f454c46",
            "/xj",
            "aflj",
            "agfj",
            "izzj",
            "ij",
            "iS",
            "iSj",
            "is",
            "isj",
            "ii",
            "iij",
            "axt",
            "axtj",
            "axf",
            "axfj",
            "pdf",
            "pdfj",
        ] {
            assert_eq!(
                router.classify_command(command),
                CommandDisposition::Native,
                "{command}"
            );
        }
    }

    #[test]
    fn classifies_known_fallback_commands() {
        let router = DefaultR2Compatibility;

        for command in ["aaa", "px 64", "pxj 64", "s 0x401000"] {
            assert_eq!(
                router.classify_command(command),
                CommandDisposition::Fallback,
                "{command}"
            );
        }
    }

    #[test]
    fn unknown_and_empty_commands_are_unsupported() {
        let router = DefaultR2Compatibility;

        for command in ["", "   ", "does-not-exist"] {
            assert_eq!(
                router.classify_command(command),
                CommandDisposition::Unsupported,
                "{command}"
            );
        }
    }

    #[test]
    fn executor_refuses_native_and_unknown_commands_without_spawning() {
        let executor = R2FallbackExecutor::new(
            "definitely-not-a-real-radare2-binary",
            Duration::from_millis(1),
        );

        assert_eq!(
            executor.execute("sample.bin", "afl"),
            Err(FallbackError::NotFallback(CommandDisposition::Native))
        );
        assert_eq!(
            executor.execute("sample.bin", "unknown-command"),
            Err(FallbackError::NotFallback(CommandDisposition::Unsupported))
        );
    }

    #[test]
    fn fallback_spawn_failure_is_explicit() {
        let executor = R2FallbackExecutor::new(
            "definitely-not-a-real-radare2-binary",
            Duration::from_millis(1),
        );

        assert_eq!(
            executor.execute("sample.bin", "aaa"),
            Err(FallbackError::Spawn)
        );
    }
}
