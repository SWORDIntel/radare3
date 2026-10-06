#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const CACHE_KEY_DOMAIN: &[u8] = b"radare3-cache-key-v1";
const CACHE_FILE_MAGIC: &[u8; 8] = b"R3CACHE\0";
const CACHE_FILE_VERSION: u32 = 1;
pub const CURRENT_ANALYSIS_SCHEMA: u32 = 1;
pub const DEFAULT_MAX_CACHE_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheKey(pub [u8; 32]);

impl CacheKey {
    pub fn derive(identity: &CacheIdentity<'_>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hash_component(&mut hasher, CACHE_KEY_DOMAIN);
        hash_component(&mut hasher, identity.binary);
        hash_component(&mut hasher, identity.loader_version.as_bytes());
        hash_component(&mut hasher, identity.decoder_version.as_bytes());
        hash_component(&mut hasher, &identity.analysis_schema.to_le_bytes());
        hash_component(&mut hasher, identity.options_fingerprint);

        Self(*hasher.finalize().as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CacheIdentity<'a> {
    pub binary: &'a [u8],
    pub loader_version: &'a str,
    pub decoder_version: &'a str,
    pub analysis_schema: u32,
    pub options_fingerprint: &'a [u8],
}

impl<'a> CacheIdentity<'a> {
    pub const fn new(
        binary: &'a [u8],
        loader_version: &'a str,
        decoder_version: &'a str,
        options_fingerprint: &'a [u8],
    ) -> Self {
        Self {
            binary,
            loader_version,
            decoder_version,
            analysis_schema: CURRENT_ANALYSIS_SCHEMA,
            options_fingerprint,
        }
    }

    pub const fn with_schema(mut self, analysis_schema: u32) -> Self {
        self.analysis_schema = analysis_schema;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheError {
    Corrupt,
    IncompatibleVersion,
    Io,
    TooLarge,
}

impl From<io::Error> for CacheError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

pub trait AnalysisCache: Send + Sync {
    fn contains(&self, key: CacheKey) -> Result<bool, CacheError>;
    fn get(&self, key: CacheKey) -> Result<Option<Vec<u8>>, CacheError>;
    fn put(&self, key: CacheKey, payload: &[u8]) -> Result<(), CacheError>;
}

#[derive(Clone, Debug)]
pub struct FileCache {
    root: PathBuf,
    max_payload_bytes: u64,
}

impl FileCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_payload_bytes: DEFAULT_MAX_CACHE_PAYLOAD_BYTES,
        }
    }

    pub fn with_max_payload_bytes(mut self, max_payload_bytes: u64) -> Self {
        self.max_payload_bytes = max_payload_bytes;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, key: CacheKey) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(&hex[..2]).join(format!("{hex}.r3c"))
    }

    fn temp_path_for(&self, key: CacheKey) -> PathBuf {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let final_path = self.path_for(key);
        let file_name = format!(".{}.{}.{}.tmp", key, std::process::id(), sequence);
        final_path
            .parent()
            .map(|parent| parent.join(&file_name))
            .unwrap_or_else(|| self.root.join(&file_name))
    }
}

impl AnalysisCache for FileCache {
    fn contains(&self, key: CacheKey) -> Result<bool, CacheError> {
        Ok(self.path_for(key).try_exists()?)
    }

    fn get(&self, key: CacheKey) -> Result<Option<Vec<u8>>, CacheError> {
        let path = self.path_for(key);
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        let mut magic = [0_u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != CACHE_FILE_MAGIC {
            return Err(CacheError::Corrupt);
        }

        let version = read_u32(&mut file)?;
        if version != CACHE_FILE_VERSION {
            return Err(CacheError::IncompatibleVersion);
        }

        let mut stored_key = [0_u8; 32];
        file.read_exact(&mut stored_key)?;
        if stored_key != key.0 {
            return Err(CacheError::Corrupt);
        }

        let payload_len = read_u64(&mut file)?;
        if payload_len > self.max_payload_bytes {
            return Err(CacheError::TooLarge);
        }

        let payload_len = usize::try_from(payload_len).map_err(|_| CacheError::TooLarge)?;
        let mut expected_hash = [0_u8; 32];
        file.read_exact(&mut expected_hash)?;

        let mut payload = vec![0_u8; payload_len];
        file.read_exact(&mut payload)?;

        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing)? != 0 {
            return Err(CacheError::Corrupt);
        }

        if blake3::hash(&payload).as_bytes() != &expected_hash {
            return Err(CacheError::Corrupt);
        }

        Ok(Some(payload))
    }

    fn put(&self, key: CacheKey, payload: &[u8]) -> Result<(), CacheError> {
        let payload_len = u64::try_from(payload.len()).map_err(|_| CacheError::TooLarge)?;
        if payload_len > self.max_payload_bytes {
            return Err(CacheError::TooLarge);
        }

        let final_path = self.path_for(key);
        if final_path.try_exists()? {
            return Ok(());
        }

        let parent = final_path.parent().ok_or(CacheError::Io)?;
        fs::create_dir_all(parent)?;

        let temp_path = self.temp_path_for(key);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;

        let write_result = (|| -> Result<(), CacheError> {
            file.write_all(CACHE_FILE_MAGIC)?;
            file.write_all(&CACHE_FILE_VERSION.to_le_bytes())?;
            file.write_all(key.as_bytes())?;
            file.write_all(&payload_len.to_le_bytes())?;
            file.write_all(blake3::hash(payload).as_bytes())?;
            file.write_all(payload)?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        match fs::rename(&temp_path, &final_path) {
            Ok(()) => Ok(()),
            Err(_) if final_path.try_exists()? => {
                let _ = fs::remove_file(&temp_path);
                Ok(())
            }
            Err(error) => {
                let _ = fs::remove_file(&temp_path);
                Err(error.into())
            }
        }
    }
}

fn hash_component(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn read_u32(reader: &mut impl Read) -> Result<u32, CacheError> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> Result<u64, CacheError> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity<'a>() -> CacheIdentity<'a> {
        CacheIdentity::new(
            b"binary bytes",
            "goblin-0.10.7/radare3-loader-v1",
            "iced-x86-1.21.0/radare3-x86-v1",
            b"deterministic=true;entrypoints=[];max_instructions=none",
        )
    }

    fn test_root(name: &str) -> PathBuf {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "radare3-cache-test-{}-{}-{sequence}",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn cache_key_is_deterministic() {
        let first = CacheKey::derive(&identity());
        let second = CacheKey::derive(&identity());

        assert_eq!(first, second);
        assert_eq!(first.to_string().len(), 64);
        assert_eq!(first.to_hex(), first.to_string());
    }

    #[test]
    fn every_identity_component_changes_the_key() {
        let base = CacheKey::derive(&identity());

        let variants = [
            CacheIdentity::new(
                b"binary bytes changed",
                identity().loader_version,
                identity().decoder_version,
                identity().options_fingerprint,
            ),
            CacheIdentity::new(
                identity().binary,
                "loader-v2",
                identity().decoder_version,
                identity().options_fingerprint,
            ),
            CacheIdentity::new(
                identity().binary,
                identity().loader_version,
                "decoder-v2",
                identity().options_fingerprint,
            ),
            CacheIdentity::new(
                identity().binary,
                identity().loader_version,
                identity().decoder_version,
                b"different-options",
            ),
            identity().with_schema(CURRENT_ANALYSIS_SCHEMA + 1),
        ];

        for variant in variants {
            assert_ne!(CacheKey::derive(&variant), base);
        }
    }

    #[test]
    fn length_prefixes_prevent_component_ambiguity() {
        let left = CacheIdentity::new(b"ab", "c", "d", b"ef");
        let right = CacheIdentity::new(b"a", "bc", "d", b"ef");

        assert_ne!(CacheKey::derive(&left), CacheKey::derive(&right));
    }

    #[test]
    fn file_cache_round_trips_and_detects_corruption() -> Result<(), CacheError> {
        let root = test_root("roundtrip");
        let cache = FileCache::new(&root);
        let key = CacheKey::derive(&identity());
        let payload = b"opaque deterministic analysis payload";

        assert!(!cache.contains(key)?);
        assert_eq!(cache.get(key)?, None);

        cache.put(key, payload)?;
        assert!(cache.contains(key)?);
        assert_eq!(cache.get(key)?, Some(payload.to_vec()));

        let path = cache.path_for(key);
        fs::write(&path, b"NOTCACHE-corrupt")?;
        assert_eq!(cache.get(key), Err(CacheError::Corrupt));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn file_cache_enforces_payload_limit() {
        let root = test_root("limit");
        let cache = FileCache::new(&root).with_max_payload_bytes(4);
        let key = CacheKey::derive(&identity());

        assert_eq!(cache.put(key, b"12345"), Err(CacheError::TooLarge));

        let _ = fs::remove_dir_all(root);
    }
}
