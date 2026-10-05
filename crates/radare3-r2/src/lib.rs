#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDisposition {
    Native,
    Fallback,
    Unsupported,
}

pub trait R2Compatibility: Send + Sync {
    fn classify_command(&self, command: &str) -> CommandDisposition;
}
