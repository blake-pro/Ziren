mod syscall;
mod instruction;
mod opcode;
mod opcode_specific;

pub use syscall::*;
pub use instruction::*;
pub use opcode::*;
pub use opcode_specific::*;
pub use syscall::*;

use p3_util::indices_arr;
use std::mem::{size_of, transmute};
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;

use crate::memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols};

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

/// The column layout for the CPU.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    /// The current shard.
    pub shard: T,

    pub nonce: T,

    /// The clock cycle value.  This should be within 24 bits.
    pub clk: T,
    /// The least significant 16 bit limb of clk.
    pub clk_16bit_limb: T,
    /// The most significant 8 bit limb of clk.
    pub clk_8bit_limb: T,

    /// The program counter value.
    pub pc: T,

    /// The expected next program counter value.
    pub next_pc: T,

    /// The expected next_next program counter value.
    pub next_next_pc: T,

    /// Columns related to the instruction.
    pub instruction: InstructionCols<T>,

    /// Selectors for the opcode.
    pub selectors: OpcodeSelectorCols<T>,

    /// Operand values, either from registers or immediate values.
    pub op_hi_access: MemoryReadWriteCols<T>,
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,

    pub opcode_specific_columns: OpcodeSpecificCols<T>,

    /// Selector to label whether this row is a non padded row.
    pub is_real: T,

    pub unsigned_mem_val_nonce: T,

    /// The result of selectors.is_syscall * the send_to_table column for the syscall opcode.
    pub syscall_mul_send_to_table: T,

    /// The result of selectors.is_syscall * (is_halt || is_commit_deferred_proofs)
    pub syscall_range_check_operand: T,

    /// This is true for all instructions that are not jumps, branches, and halt.  Those
    /// instructions may move the program counter to a non sequential instruction.
    pub is_sequential_instr: T,

    pub op_a_immutable: T,
}

impl<T: Copy> CpuCols<T> {
    /// Gets the value of the upper bits of the output operand.
    pub fn op_hi_val(&self) -> Word<T> {
        *self.op_hi_access.value()
    }

    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<T> {
        *self.op_a_access.value()
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        *self.op_b_access.value()
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        *self.op_c_access.value()
    }
}

/// Creates the column map for the CPU.
const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}
