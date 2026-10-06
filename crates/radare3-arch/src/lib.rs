#![forbid(unsafe_code)]

use radare3_types::Address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKind {
    Fallthrough,
    Branch,
    ConditionalBranch,
    Call,
    Return,
    Trap,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedInstruction {
    pub address: Address,
    pub length: u8,
    pub flow: FlowKind,
    pub target: Option<Address>,
    pub data_target: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidInstruction,
    InsufficientBytes,
    Unsupported,
}

pub trait Decoder: Send + Sync {
    fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, DecodeError>;
}
