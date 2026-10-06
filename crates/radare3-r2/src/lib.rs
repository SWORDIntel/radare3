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

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultR2Compatibility;

impl R2Compatibility for DefaultR2Compatibility {
    fn classify_command(&self, command: &str) -> CommandDisposition {
        let Some(head) = command.split_ascii_whitespace().next() else {
            return CommandDisposition::Unsupported;
        };

        match head {
            "afl" | "agf" | "izz" | "/x" => CommandDisposition::Native,
            "aaa" | "afi" | "pdf" | "axt" | "axf" | "is" | "iS" | "px" | "s" | "/xj" | "aflj"
            | "agfj" | "izzj" | "ij" => CommandDisposition::Fallback,
            _ => CommandDisposition::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_native_commands() {
        let router = DefaultR2Compatibility;

        for command in ["afl", "agf", "izz", "/x", "/x 7f454c46"] {
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

        for command in [
            "aaa",
            "afi 0x401000",
            "pdf",
            "axt",
            "axf",
            "is",
            "iS",
            "px 64",
            "s 0x401000",
            "/xj 7f454c46",
            "aflj",
            "agfj",
            "izzj",
            "ij",
        ] {
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
}
