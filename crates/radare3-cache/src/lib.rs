#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheKey(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheError {
    Corrupt,
    IncompatibleVersion,
    Io,
}

pub trait AnalysisCache: Send + Sync {
    fn contains(&self, key: CacheKey) -> Result<bool, CacheError>;
}
