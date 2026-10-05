#![forbid(unsafe_code)]

use std::sync::Arc;

use radare3_image::BinaryImage;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoadError {
    Malformed,
    UnsupportedFormat,
    UnsupportedArchitecture,
}

pub trait Loader: Send + Sync {
    fn load(&self, bytes: Arc<[u8]>) -> Result<BinaryImage, LoadError>;
}
