use super::{create_random_lookup_ids, LookupId};
use crate::Opcode;
use super::MemoryRecordEnum;
use serde::{Deserialize, Serialize};

/// Arithmetic Logic Unit (ALU) Event.
///
/// This object encapsulated the information needed to prove an ALU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    /// The lookup identifier.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The upper bits of the output operand.
    /// This is used for the MULT, MULTU, DIV and DIVU opcodes.
    pub hi: u32,
    /// The output operand.
    pub a: u32,
    /// The first input operand.
    pub b: u32,
    /// The second input operand.
    pub c: u32,
    /// The result of the operation in the format of [``LookupId``; 5]
    pub sub_lookups: [LookupId; 5],
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(shard: u32, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self {
            lookup_id: LookupId::default(),
            shard,
            clk,
            opcode,
            a,
            b,
            c,
            hi: 0,
            sub_lookups: create_random_lookup_ids(),
        }
    }

    /// Create a new [`AluEvent`].
    /// Used for opcode with LO and HI registers
    /// DIV DIVU MULT MULLTU
    #[must_use]
    pub fn new_with_hi(shard: u32, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32, hi: u32) -> Self {
        Self {
            lookup_id: LookupId::default(),
            shard,
            clk,
            opcode,
            a,
            b,
            c,
            hi,
            sub_lookups: create_random_lookup_ids(),
        }
    }
}


/// Memory Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V memory operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct MemInstrEvent {
    /// The shard.
    pub shard: u32,
    /// The clk.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
    /// The memory access record for memory operations.
    pub mem_access: MemoryRecordEnum,
}

impl MemInstrEvent {
    /// Create a new [`MemInstrEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard: u32,
        clk: u32,
        pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
        mem_access: MemoryRecordEnum,
    ) -> Self {
        Self { shard, clk, pc, opcode, a, b, c, op_a_0, mem_access }
    }
}

/// Branch Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V branch operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct BranchEvent {
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The next program counter.
    pub next_next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
}

impl BranchEvent {
    /// Create a new [`BranchEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pc: u32,
        next_pc: u32,
        next_next_pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
    ) -> Self {
        Self { pc, next_pc, next_next_pc, opcode, a, b, c, op_a_0 }
    }
}

/// Jump Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V jump operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct JumpEvent {
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
}

impl JumpEvent {
    /// Create a new [`JumpEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pc: u32,
        next_pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
    ) -> Self {
        Self { pc, next_pc, opcode, a, b, c, op_a_0 }
    }
}
