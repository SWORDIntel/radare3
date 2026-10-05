#![forbid(unsafe_code)]

use std::sync::Arc;

use radare3_types::{Address, Architecture, BinaryFormat};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment {
    pub name: String,
    pub address: Address,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub permissions: Permissions,
}

#[derive(Clone, Debug)]
pub struct BinaryImage {
    bytes: Arc<[u8]>,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub base_address: Address,
    pub segments: Vec<Segment>,
}

impl BinaryImage {
    pub fn new(
        bytes: Arc<[u8]>,
        format: BinaryFormat,
        architecture: Architecture,
        base_address: Address,
        segments: Vec<Segment>,
    ) -> Self {
        Self {
            bytes,
            format,
            architecture,
            base_address,
            segments,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
