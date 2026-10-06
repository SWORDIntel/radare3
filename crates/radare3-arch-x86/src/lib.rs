#![forbid(unsafe_code)]

use iced_x86::{Decoder as IcedDecoderCore, DecoderOptions, FastFormatter, FlowControl, OpKind};
use radare3_arch::{DecodeError, DecodedInstruction, Decoder, FlowKind};
use radare3_types::Address;

pub const DECODER_SEMANTICS_VERSION: &str = "iced-x86-1.21.0/radare3-x86-v2-data-xrefs";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisassembledInstruction {
    pub address: Address,
    pub length: u8,
    pub text: String,
}

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

impl IcedX86Decoder {
    pub fn disassemble(
        &self,
        address: Address,
        bytes: &[u8],
    ) -> Result<Vec<DisassembledInstruction>, DecodeError> {
        let mut decoder =
            IcedDecoderCore::with_ip(self.bitness, bytes, address.0, DecoderOptions::NONE);
        let mut formatter = FastFormatter::new();
        formatter
            .options_mut()
            .set_space_after_operand_separator(true);
        let mut output = String::new();
        let mut instructions = Vec::new();

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                return Err(DecodeError::InvalidInstruction);
            }

            let length =
                u8::try_from(instruction.len()).map_err(|_| DecodeError::InvalidInstruction)?;
            output.clear();
            formatter.format(&instruction, &mut output);
            instructions.push(DisassembledInstruction {
                address: Address(instruction.ip()),
                length,
                text: output.clone(),
            });
        }

        Ok(instructions)
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
        let data_target = instruction
            .is_ip_rel_memory_operand()
            .then(|| Address(instruction.ip_rel_memory_address()));

        Ok(DecodedInstruction {
            address,
            length,
            flow,
            target,
            data_target,
        })
    }
}

fn map_flow(flow: FlowControl) -> FlowKind {
    match flow {
        FlowControl::Next => FlowKind::Fallthrough,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => FlowKind::Branch,
        FlowControl::ConditionalBranch => FlowKind::ConditionalBranch,
        FlowControl::Call | FlowControl::IndirectCall => FlowKind::Call,
        FlowControl::Return => FlowKind::Return,
        FlowControl::Interrupt | FlowControl::Exception => FlowKind::Trap,
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
        assert_eq!(decoded.data_target, None);

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
        assert_eq!(decoded.data_target, None);

        Ok(())
    }

    #[test]
    fn decodes_rip_relative_data_target() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = IcedX86Decoder::x86_64()
            .decode(
                Address(0x401000),
                &[0x48, 0x8b, 0x05, 0x34, 0x12, 0x00, 0x00],
            )
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(decoded.length, 7);
        assert_eq!(decoded.flow, FlowKind::Fallthrough);
        assert_eq!(decoded.target, None);
        assert_eq!(decoded.data_target, Some(Address(0x40223b)));

        Ok(())
    }

    #[test]
    fn fast_disassembly_preserves_addresses_lengths_and_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let instructions = IcedX86Decoder::x86_64()
            .disassemble(Address(0x401000), &[0x55, 0x48, 0x89, 0xe5, 0xc3])
            .map_err(|error| format!("disassembly failed: {error:?}"))?;

        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].address, Address(0x401000));
        assert_eq!(instructions[0].length, 1);
        assert_eq!(instructions[0].text, "push rbp");
        assert_eq!(instructions[1].address, Address(0x401001));
        assert_eq!(instructions[1].length, 3);
        assert_eq!(instructions[1].text, "mov rbp, rsp");
        assert_eq!(instructions[2].address, Address(0x401004));
        assert_eq!(instructions[2].text, "ret");

        Ok(())
    }

    #[test]
    fn disassembly_rejects_invalid_instruction() {
        assert_eq!(
            IcedX86Decoder::x86_64().disassemble(Address(0x401000), &[0x0f]),
            Err(DecodeError::InvalidInstruction)
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(
            IcedX86Decoder::x86_64().decode(Address(0), &[]),
            Err(DecodeError::InsufficientBytes)
        );
    }
}
