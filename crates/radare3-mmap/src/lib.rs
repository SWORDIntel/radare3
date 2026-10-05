#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

use memmap2::MmapOptions;
use radare3_image::BinaryData;

pub fn map_file(path: impl AsRef<Path>) -> io::Result<BinaryData> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "radare3 mmap input must be a regular file",
        ));
    }

    if metadata.len() == 0 {
        return Ok(BinaryData::owned(Arc::<[u8]>::from([])));
    }

    // SAFETY: radare3 creates a read-only mapping and never mutates the mapped
    // file through this handle. As with all file-backed mmap APIs, callers must
    // not truncate or concurrently rewrite the target while analysis is active.
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    Ok(BinaryData::mapped(Arc::new(mmap)))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn maps_regular_file_without_copying() -> io::Result<()> {
        let path = std::env::temp_dir().join(format!("radare3-mmap-{}.bin", std::process::id()));
        fs::write(&path, b"radare3")?;

        let data = map_file(&path)?;
        assert!(data.is_mapped());
        assert_eq!(data.as_slice(), b"radare3");

        fs::remove_file(path)?;
        Ok(())
    }
}
