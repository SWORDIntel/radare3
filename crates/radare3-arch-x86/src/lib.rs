#![forbid(unsafe_code)]

use iced_x86::{Decoder as IcedDecoderCore, DecoderOptions, FlowControl, OpKind};
use radare3_arch::{DecodeError, DecodedInstruction, Decoder, FlowKind};
use radare3_types::Address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcedX86Decoder {
    bitness: u32,
}

impl IcedX86Decoder {
    pub const fn x86() -> Self {
        Self { bitness: 32 }
    }

    pub const fn x86_64() -> Self {
        Self { bitness: 64 }
    }
}

impl Decoder for IcedX86Decoder {
    fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::InsufficientBytes);
        }

        let mut decoder =
            IcedDecoderCore::with_ip(self.bitness, bytes, address.0, DecoderOptions::NONE);
        let instruction = decoder.decode();

        if instruction.is_invalid() {
            return Err(DecodeError::InvalidInstruction);
        }

        let length =
            u8::try_from(instruction.len()).map_err(|_| DecodeError::InvalidInstruction)?;
        let flow = map_flow(instruction.flow_control());
        let target = match instruction.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(Address(instruction.near_branch_target()))
            }
            _ => None,
        };

        Ok(DecodedInstruction {
            address,
            length,
            flow,
            target,
        })
    }
}

fn map_flow(flow: FlowControl) -> FlowKind {
    match flow {
        FlowControl::Next => FlowKind::Fallthrough,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => FlowKind::Branch,
        FlowControl::ConditionalBranch => FlowKind::ConditionalBranch,
        FlowControl::Call | FlowControl::IndirectCall => FlowKind::Call,
        FlowControl::Return | FlowControl::SystemReturn => FlowKind::Return,
        FlowControl::Interrupt | FlowControl::Exception | FlowControl::SystemCall => FlowKind::Trap,
        _ => FlowKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ret() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = IcedX86Decoder::x86_64()
            .decode(Address(0x401000), &[0xc3])
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(decoded.length, 1);
        assert_eq!(decoded.flow, FlowKind::Return);
        assert_eq!(decoded.target, None);

        Ok(())
    }

    #[test]
    fn decodes_relative_call_target() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = IcedX86Decoder::x86_64()
            .decode(Address(0x401000), &[0xe8, 0x05, 0x00, 0x00, 0x00])
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(decoded.length, 5);
        assert_eq!(decoded.flow, FlowKind::Call);
        assert_eq!(decoded.target, Some(Address(0x40100a)));

        Ok(())
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(
            IcedX86Decoder::x86_64().decode(Address(0), &[]),
            Err(DecodeError::InsufficientBytes)
        );
    }
}
