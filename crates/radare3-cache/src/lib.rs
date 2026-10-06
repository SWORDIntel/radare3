#![forbid(unsafe_code)]

use std::fmt;

const CACHE_KEY_DOMAIN: &[u8] = b"radare3-cache-key-v1";
pub const CURRENT_ANALYSIS_SCHEMA: u32 = 1;

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
}

pub trait AnalysisCache: Send + Sync {
    fn contains(&self, key: CacheKey) -> Result<bool, CacheError>;
}

fn hash_component(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
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
}
