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

impl Segment {
    pub fn contains_file_address(&self, address: Address) -> bool {
        let Some(end) = self.address.0.checked_add(self.file_size) else {
            return false;
        };
        address.0 >= self.address.0 && address.0 < end
    }
}

#[derive(Clone, Debug)]
pub struct BinaryImage {
    bytes: Arc<[u8]>,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub base_address: Address,
    pub entry_point: Option<Address>,
    pub segments: Vec<Segment>,
}

impl BinaryImage {
    pub fn new(
        bytes: Arc<[u8]>,
        format: BinaryFormat,
        architecture: Architecture,
        base_address: Address,
        entry_point: Option<Address>,
        segments: Vec<Segment>,
    ) -> Self {
        Self {
            bytes,
            format,
            architecture,
            base_address,
            entry_point,
            segments,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn address_to_file_offset(&self, address: Address) -> Option<usize> {
        self.segments.iter().find_map(|segment| {
            if !segment.contains_file_address(address) {
                return None;
            }

            let delta = address.0.checked_sub(segment.address.0)?;
            let offset = segment.file_offset.checked_add(delta)?;
            usize::try_from(offset).ok()
        })
    }

    pub fn bytes_at(&self, address: Address, max_len: usize) -> Option<&[u8]> {
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.contains_file_address(address))?;

        let offset = self.address_to_file_offset(address)?;
        let delta = address.0.checked_sub(segment.address.0)?;
        let remaining = segment.file_size.checked_sub(delta)?;
        let remaining = usize::try_from(remaining).ok()?;
        let len = max_len.min(remaining);
        let end = offset.checked_add(len)?;

        self.bytes.get(offset..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_virtual_address_to_file_offset() {
        let image = BinaryImage::new(
            Arc::from([0_u8; 32]),
            BinaryFormat::Raw,
            Architecture::Unknown,
            Address(0x1000),
            None,
            vec![Segment {
                name: "test".to_string(),
                address: Address(0x1000),
                file_offset: 4,
                file_size: 8,
                memory_size: 16,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
        );

        assert_eq!(image.address_to_file_offset(Address(0x1003)), Some(7));
        assert_eq!(image.address_to_file_offset(Address(0x1008)), None);
        assert_eq!(
            image.bytes_at(Address(0x1006), 15).map(<[u8]>::len),
            Some(2)
        );
    }
}
