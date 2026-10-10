#![forbid(unsafe_code)]

use iced_x86::{
    Code, Decoder as IcedDecoderCore, DecoderOptions, FastFormatter, FlowControl, OpKind, Register,
};
use radare3_arch::{DecodeError, DecodedInstruction, Decoder, FlowKind};
use radare3_types::Address;

pub const DECODER_SEMANTICS_VERSION: &str = "iced-x86-1.21.0/radare3-x86-v3-absolute-data-xrefs";
/// Exact iced-x86 crate version pinned by this workspace's lockfile.
pub const ICED_X86_DECODER_VERSION: &str = "1.21.0";
pub const ICED_X86_HANDOFF_SCHEMA: &str = "radare3.iced-x86.decode-handoff.v1";

/// Canonical-identity state for a provider decode result.
///
/// ISANITY's checked-in form identities are fixtures/proposals, not a ratified
/// real-instruction catalogue. Keep this explicitly unresolved until a reviewed
/// mapping artifact exists; provider enum values must never be promoted by name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalMapping {
    Unresolved { reason: &'static str },
}

/// Library-level handoff envelope retaining iced-x86 identity without claiming
/// that its version-scoped `Code` value is a cross-decoder identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcedX86HandoffV1 {
    pub schema: &'static str,
    pub provider: &'static str,
    pub provider_version: &'static str,
    pub architecture: &'static str,
    pub execution_mode: String,
    pub input_bytes: Vec<u8>,
    pub consumed_bytes: Vec<u8>,
    pub source_namespace: &'static str,
    pub source_name: String,
    pub source_numeric_value: u32,
    pub canonical_mapping: CanonicalMapping,
}

/// Decoder output with the native iced-x86 code identity attached.
///
/// `code_name` is iced-x86's `Code` enum variant name. It is decoder metadata,
/// not a canonical ISANITY identity or a claim about instruction semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedInstructionWithCode {
    pub decoded: DecodedInstruction,
    pub code: Code,
    /// Numeric discriminant of iced-x86's version-scoped `Code` enum.
    pub code_discriminant: u32,
    pub code_name: String,
    pub decoder_version: &'static str,
    /// No canonical ISANITY identity mapping is defined by this decoder yet.
    pub canonical_isanity_id: Option<&'static str>,
}

/// Reproducible, provider-scoped observation for one decode request.
///
/// `input_bytes` retains the complete caller-supplied slice; `decoded_bytes`
/// contains only the bytes consumed for this instruction. The Code identity
/// is specific to the pinned iced-x86 version and is not canonical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcedX86Observation {
    pub address: Address,
    pub bitness: u32,
    pub input_bytes: Vec<u8>,
    pub decoded_bytes: Vec<u8>,
    pub code_discriminant: u32,
    pub code_name: String,
    pub decoder_version: &'static str,
    pub decoded: DecodedInstruction,
    /// No canonical ISANITY identity mapping is defined by this decoder yet.
    pub canonical_isanity_id: Option<&'static str>,
}

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
    /// Decode once and return the existing instruction record plus iced-x86 metadata.
    pub fn decode_with_code(
        &self,
        address: Address,
        bytes: &[u8],
    ) -> Result<DecodedInstructionWithCode, DecodeError> {
        let (decoded, code) = decode_native(self.bitness, address, bytes)?;
        Ok(DecodedInstructionWithCode {
            decoded,
            code,
            code_discriminant: code as u32,
            code_name: format!("{code:?}"),
            decoder_version: ICED_X86_DECODER_VERSION,
            canonical_isanity_id: None,
        })
    }

    /// Decode a single instruction while retaining provider-scoped evidence.
    pub fn observe(
        &self,
        address: Address,
        bytes: &[u8],
    ) -> Result<IcedX86Observation, DecodeError> {
        let result = self.decode_with_code(address, bytes)?;
        let decoded_bytes = bytes
            .get(..result.decoded.length as usize)
            .ok_or(DecodeError::InvalidInstruction)?
            .to_vec();
        Ok(IcedX86Observation {
            address,
            bitness: self.bitness,
            input_bytes: bytes.to_vec(),
            decoded_bytes,
            code_discriminant: result.code_discriminant,
            code_name: result.code_name,
            decoder_version: result.decoder_version,
            decoded: result.decoded,
            canonical_isanity_id: result.canonical_isanity_id,
        })
    }

    /// Create the versioned identity handoff from the same decode operation.
    /// No ID is invented when ISANITY has not ratified an applicable form row.
    pub fn observe_handoff_v1(
        &self,
        address: Address,
        bytes: &[u8],
    ) -> Result<IcedX86HandoffV1, DecodeError> {
        let observation = self.observe(address, bytes)?;
        Ok(IcedX86HandoffV1 {
            schema: ICED_X86_HANDOFF_SCHEMA,
            provider: "iced-x86",
            provider_version: observation.decoder_version,
            architecture: "x86",
            execution_mode: format!("{}-bit", observation.bitness),
            input_bytes: observation.input_bytes,
            consumed_bytes: observation.decoded_bytes,
            source_namespace: "iced-x86::Code",
            source_name: observation.code_name,
            source_numeric_value: observation.code_discriminant,
            canonical_mapping: CanonicalMapping::Unresolved {
                reason: "no ratified ISANITY catalogue mapping is available",
            },
        })
    }

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
        decode_native(self.bitness, address, bytes).map(|(decoded, _)| decoded)
    }
}

fn decode_native(
    bitness: u32,
    address: Address,
    bytes: &[u8],
) -> Result<(DecodedInstruction, Code), DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::InsufficientBytes);
    }

    let mut decoder = IcedDecoderCore::with_ip(bitness, bytes, address.0, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(DecodeError::InvalidInstruction);
    }

    let length = u8::try_from(instruction.len()).map_err(|_| DecodeError::InvalidInstruction)?;
    let flow = map_flow(instruction.flow_control());
    let target = match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(Address(instruction.near_branch_target()))
        }
        _ => None,
    };
    let data_target = memory_data_target(&instruction);
    Ok((
        DecodedInstruction {
            address,
            length,
            flow,
            target,
            data_target,
        },
        instruction.code(),
    ))
}

fn memory_data_target(instruction: &iced_x86::Instruction) -> Option<Address> {
    if instruction.is_ip_rel_memory_operand() {
        return Some(Address(instruction.ip_rel_memory_address()));
    }

    let has_explicit_memory =
        (0..instruction.op_count()).any(|operand| instruction.op_kind(operand) == OpKind::Memory);

    if has_explicit_memory
        && instruction.memory_base() == Register::None
        && instruction.memory_index() == Register::None
    {
        Some(Address(instruction.memory_displacement64()))
    } else {
        None
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
    fn exposes_native_mov_code_and_version() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = IcedX86Decoder::x86_64()
            .decode_with_code(Address(0x401000), &[0x48, 0x89, 0xe5])
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(decoded.code_name, "Mov_rm64_r64");
        assert_eq!(decoded.code_name, format!("{:?}", decoded.code));
        assert_eq!(decoded.code_discriminant, decoded.code as u32);
        assert_eq!(decoded.decoder_version, "1.21.0");
        assert_eq!(decoded.canonical_isanity_id, None);
        assert_eq!(decoded.decoded.length, 3);
        Ok(())
    }

    #[test]
    fn observation_preserves_mode_complete_input_and_consumed_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let observation = IcedX86Decoder::x86_64()
            .observe(Address(0x401000), &[0x48, 0x89, 0xe5, 0x90])
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(observation.address, Address(0x401000));
        assert_eq!(observation.bitness, 64);
        assert_eq!(observation.input_bytes, [0x48, 0x89, 0xe5, 0x90]);
        assert_eq!(observation.decoded_bytes, [0x48, 0x89, 0xe5]);
        assert_eq!(observation.code_name, "Mov_rm64_r64");
        assert_eq!(observation.code_discriminant, Code::Mov_rm64_r64 as u32);
        assert_eq!(observation.decoder_version, ICED_X86_DECODER_VERSION);
        assert_eq!(observation.canonical_isanity_id, None);
        Ok(())
    }

    #[test]
    fn handoff_v1_preserves_provider_namespace_mode_version_and_consumption()
    -> Result<(), Box<dyn std::error::Error>> {
        let handoff = IcedX86Decoder::x86_64()
            .observe_handoff_v1(Address(0x401000), &[0x48, 0x89, 0xe5, 0x90])
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(handoff.schema, ICED_X86_HANDOFF_SCHEMA);
        assert_eq!(handoff.provider, "iced-x86");
        assert_eq!(handoff.provider_version, "1.21.0");
        assert_eq!(handoff.architecture, "x86");
        assert_eq!(handoff.execution_mode, "64-bit");
        assert_eq!(handoff.input_bytes, [0x48, 0x89, 0xe5, 0x90]);
        assert_eq!(handoff.consumed_bytes, [0x48, 0x89, 0xe5]);
        assert_eq!(handoff.source_namespace, "iced-x86::Code");
        assert_eq!(handoff.source_name, "Mov_rm64_r64");
        assert_eq!(handoff.source_numeric_value, Code::Mov_rm64_r64 as u32);
        assert_eq!(
            handoff.canonical_mapping,
            CanonicalMapping::Unresolved {
                reason: "no ratified ISANITY catalogue mapping is available"
            }
        );

        let legacy_handoff = IcedX86Decoder::x86()
            .observe_handoff_v1(Address(0x401000), &[0x89, 0xe5, 0x90])
            .map_err(|error| format!("decode failed: {error:?}"))?;
        assert_eq!(legacy_handoff.execution_mode, "32-bit");
        assert_eq!(legacy_handoff.provider_version, handoff.provider_version);
        assert_eq!(legacy_handoff.source_namespace, handoff.source_namespace);
        assert_eq!(legacy_handoff.source_name, "Mov_rm32_r32");
        assert_eq!(legacy_handoff.consumed_bytes, [0x89, 0xe5]);
        Ok(())
    }

    #[test]
    fn handoff_v1_fails_closed_for_invalid_or_truncated_input() {
        assert_eq!(
            IcedX86Decoder::x86_64().observe_handoff_v1(Address(0), &[]),
            Err(DecodeError::InsufficientBytes)
        );
        assert_eq!(
            IcedX86Decoder::x86_64().observe_handoff_v1(Address(0), &[0x0f]),
            Err(DecodeError::InvalidInstruction)
        );
    }

    #[test]
    fn exposes_native_conditional_branch_code_without_canonical_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let decoded = IcedX86Decoder::x86_64()
            .decode_with_code(Address(0x401000), &[0x75, 0x00])
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(decoded.code_name, "Jne_rel8_64");
        assert_eq!(decoded.code_name, format!("{:?}", decoded.code));
        assert_eq!(decoded.decoded.flow, FlowKind::ConditionalBranch);
        assert_eq!(decoded.canonical_isanity_id, None);
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
    fn decodes_absolute_memory_data_target() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = IcedX86Decoder::x86_64()
            .decode(
                Address(0x401000),
                &[0x48, 0x8b, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12],
            )
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(decoded.length, 8);
        assert_eq!(decoded.flow, FlowKind::Fallthrough);
        assert_eq!(decoded.target, None);
        assert_eq!(decoded.data_target, Some(Address(0x1234_5678)));

        Ok(())
    }

    #[test]
    fn register_based_memory_does_not_claim_absolute_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let decoded = IcedX86Decoder::x86_64()
            .decode(Address(0x401000), &[0x48, 0x8b, 0x43, 0x20])
            .map_err(|error| format!("decode failed: {error:?}"))?;

        assert_eq!(decoded.length, 4);
        assert_eq!(decoded.data_target, None);

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
