#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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
            | "ij" | "iS" | "iSj" | "is" | "isj" | "axt" | "axtj" | "axf" | "axfj" => {
                CommandDisposition::Native
            }
            "aaa" | "pdf" | "px" | "pxj" | "s" => CommandDisposition::Fallback,
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
            "axt",
            "axtj",
            "axf",
            "axfj",
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

        for command in ["aaa", "pdf", "px 64", "pxj 64", "s 0x401000"] {
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
