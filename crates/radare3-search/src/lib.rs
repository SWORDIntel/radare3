#![forbid(unsafe_code)]

use radare3_image::BinaryImage;
use radare3_types::Address;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchHit {
    pub address: Address,
    pub length: usize,
}

pub trait SearchEngine: Send + Sync {
    fn find_all(&self, base: Address, haystack: &[u8], needle: &[u8]) -> Vec<SearchHit>;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExtractedString {
    pub address: Address,
    pub encoding: StringEncoding,
    pub value: String,
}

pub fn extract_strings(image: &BinaryImage, min_chars: usize) -> Vec<ExtractedString> {
    if min_chars == 0 {
        return Vec::new();
    }

    let mut strings = Vec::new();

    for segment in &image.segments {
        let Ok(start) = usize::try_from(segment.file_offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(segment.file_size) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        let Some(bytes) = image.bytes().get(start..end) else {
            continue;
        };

        extract_ascii(segment.address, bytes, min_chars, &mut strings);
        extract_utf16le(segment.address, bytes, min_chars, &mut strings);
    }

    strings.sort();
    strings.dedup();
    strings
}

fn extract_ascii(
    base: Address,
    bytes: &[u8],
    min_chars: usize,
    strings: &mut Vec<ExtractedString>,
) {
    let mut index = 0;

    while index < bytes.len() {
        if !is_printable_ascii(bytes[index]) {
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len() && is_printable_ascii(bytes[index]) {
            index += 1;
        }

        if index - start < min_chars {
            continue;
        }

        let Some(address) = add_offset(base, start) else {
            continue;
        };
        let value = String::from_utf8_lossy(&bytes[start..index]).into_owned();

        strings.push(ExtractedString {
            address,
            encoding: StringEncoding::Ascii,
            value,
        });
    }
}

fn extract_utf16le(
    base: Address,
    bytes: &[u8],
    min_chars: usize,
    strings: &mut Vec<ExtractedString>,
) {
    let mut index = 0;

    while index + 1 < bytes.len() {
        if !is_printable_ascii(bytes[index]) || bytes[index + 1] != 0 {
            index += 1;
            continue;
        }

        let start = index;
        let mut value = String::new();

        while index + 1 < bytes.len() && is_printable_ascii(bytes[index]) && bytes[index + 1] == 0 {
            value.push(char::from(bytes[index]));
            index += 2;
        }

        if value.chars().count() < min_chars {
            index = start + 1;
            continue;
        }

        let Some(address) = add_offset(base, start) else {
            continue;
        };

        strings.push(ExtractedString {
            address,
            encoding: StringEncoding::Utf16Le,
            value,
        });
    }
}

const fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}

fn add_offset(base: Address, offset: usize) -> Option<Address> {
    let offset = u64::try_from(offset).ok()?;
    base.0.checked_add(offset).map(Address)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use radare3_image::{Permissions, Segment};
    use radare3_types::{Architecture, BinaryFormat};

    use super::*;

    fn image(bytes: Vec<u8>) -> BinaryImage {
        let size = bytes.len() as u64;
        BinaryImage::new(
            Arc::from(bytes),
            BinaryFormat::Raw,
            Architecture::Unknown,
            Address(0x4000),
            None,
            vec![Segment {
                name: "data".to_string(),
                address: Address(0x4000),
                file_offset: 0,
                file_size: size,
                memory_size: size,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: false,
                },
            }],
        )
    }

    #[test]
    fn extracts_ascii_and_utf16le_strings() {
        let mut bytes = b"\0HELLO\0xx\0\0".to_vec();
        bytes.extend_from_slice(b"W\0O\0R\0L\0D\0\0\0");

        let strings = extract_strings(&image(bytes), 4);

        assert!(strings.iter().any(|string| {
            string.address == Address(0x4001)
                && string.encoding == StringEncoding::Ascii
                && string.value == "HELLO"
        }));
        assert!(strings.iter().any(|string| {
            string.encoding == StringEncoding::Utf16Le && string.value == "WORLD"
        }));
    }

    #[test]
    fn honors_minimum_length() {
        let strings = extract_strings(&image(b"abc\0abcd\0".to_vec()), 4);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "abcd");
    }
}
