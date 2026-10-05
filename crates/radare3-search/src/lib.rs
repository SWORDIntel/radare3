#![forbid(unsafe_code)]

use radare3_types::Address;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchHit {
    pub address: Address,
    pub length: usize,
}

pub trait SearchEngine: Send + Sync {
    fn find_all(&self, base: Address, haystack: &[u8], needle: &[u8]) -> Vec<SearchHit>;
}
