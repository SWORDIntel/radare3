#![forbid(unsafe_code)]

use memchr::{memchr_iter, memmem};
use radare3_image::BinaryImage;
use radare3_types::Address;
use rayon::prelude::*;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SearchHit {
    pub address: Address,
    pub length: usize,
}

pub trait SearchEngine: Send + Sync {
    fn find_all(&self, base: Address, haystack: &[u8], needle: &[u8]) -> Vec<SearchHit>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FastSearchEngine;

impl SearchEngine for FastSearchEngine {
    fn find_all(&self, base: Address, haystack: &[u8], needle: &[u8]) -> Vec<SearchHit> {
        if needle.is_empty() {
            return Vec::new();
        }

        if needle.len() == 1 {
            return memchr_iter(needle[0], haystack)
                .filter_map(|offset| {
                    add_offset(base, offset).map(|address| SearchHit { address, length: 1 })
                })
                .collect();
        }

        let finder = memmem::Finder::new(needle);
        let mut hits = Vec::new();
        let mut cursor = 0;

        while cursor <= haystack.len().saturating_sub(needle.len()) {
            let Some(relative) = finder.find(&haystack[cursor..]) else {
                break;
            };
            let offset = cursor + relative;
            if let Some(address) = add_offset(base, offset) {
                hits.push(SearchHit {
                    address,
                    length: needle.len(),
                });
            }
            cursor = offset.saturating_add(1);
        }

        hits
    }
}

pub fn find_bytes(image: &BinaryImage, needle: &[u8]) -> Vec<SearchHit> {
    let engine = FastSearchEngine;
    let mut hits: Vec<SearchHit> = image
        .segments
        .par_iter()
        .flat_map(|segment| {
            let Some(bytes) = segment_bytes(image, segment.file_offset, segment.file_size) else {
                return Vec::new();
            };
            engine.find_all(segment.address, bytes, needle)
        })
        .collect();

    hits.sort();
    hits.dedup();
    hits
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

    let mut strings: Vec<ExtractedString> = image
        .segments
        .par_iter()
        .flat_map(|segment| {
            let Some(bytes) = segment_bytes(image, segment.file_offset, segment.file_size) else {
                return Vec::new();
            };

            let mut local = Vec::new();
            extract_ascii(segment.address, bytes, min_chars, &mut local);
            extract_utf16le(segment.address, bytes, min_chars, &mut local);
            local
        })
        .collect();

    strings.sort();
    strings.dedup();
    strings
}

fn segment_bytes(image: &BinaryImage, file_offset: u64, file_size: u64) -> Option<&[u8]> {
    let start = usize::try_from(file_offset).ok()?;
    let size = usize::try_from(file_size).ok()?;
    let end = start.checked_add(size)?;
    image.bytes().get(start..end)
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

        if value.len() < min_chars {
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
    fn finds_single_and_multi_byte_patterns() {
        let engine = FastSearchEngine;
        let haystack = b"ABABA";

        assert_eq!(
            engine.find_all(Address(0x1000), haystack, b"A"),
            vec![
                SearchHit {
                    address: Address(0x1000),
                    length: 1
                },
                SearchHit {
                    address: Address(0x1002),
                    length: 1
                },
                SearchHit {
                    address: Address(0x1004),
                    length: 1
                }
            ]
        );

        assert_eq!(
            engine.find_all(Address(0x1000), haystack, b"ABA"),
            vec![
                SearchHit {
                    address: Address(0x1000),
                    length: 3
                },
                SearchHit {
                    address: Address(0x1002),
                    length: 3
                }
            ]
        );
    }

    #[test]
    fn empty_pattern_has_no_hits() {
        assert!(
            FastSearchEngine
                .find_all(Address(0), b"anything", b"")
                .is_empty()
        );
    }

    #[test]
    fn image_search_is_sorted_and_deterministic() {
        let image = image(b"XXMARKXXMARK".to_vec());
        let first = find_bytes(&image, b"MARK");
        let second = find_bytes(&image, b"MARK");

        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                SearchHit {
                    address: Address(0x4002),
                    length: 4
                },
                SearchHit {
                    address: Address(0x4008),
                    length: 4
                }
            ]
        );
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
