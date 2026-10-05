#![forbid(unsafe_code)]

use radare3_types::{Address, XrefId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XrefKind {
    Call,
    Code,
    Data,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Xref {
    pub id: XrefId,
    pub from: Address,
    pub to: Address,
    pub kind: XrefKind,
}
