use p3_field::PrimeField;
use std::{
    mem::{size_of, transmute},
    vec::IntoIter,
};
use zkm2_core_executor::{Instruction, Opcode};
use zkm2_derive::AlignedBorrow;

use crate::utils::indices_arr;

pub const NUM_OPCODE_SELECTOR_COLS: usize = size_of::<OpcodeSelectorCols<u8>>();
pub const OPCODE_SELECTORS_COL_MAP: OpcodeSelectorCols<usize> = make_selectors_col_map();

/// Creates the column map for the CPU.
const fn make_selectors_col_map() -> OpcodeSelectorCols<usize> {
    let indices_arr = indices_arr::<NUM_OPCODE_SELECTOR_COLS>();
    unsafe {
        transmute::<[usize; NUM_OPCODE_SELECTOR_COLS], OpcodeSelectorCols<usize>>(indices_arr)
    }
}

/// The column layout for opcode selectors.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    /// Whether to use the HI register.
    pub has_hi: T,

    /// Whether op_b is an immediate value.
    pub imm_b: T,

    /// Whether op_c is an immediate value.
    pub imm_c: T,

    /// Table selectors for opcodes.
    pub is_alu: T,

    /// Table selectors for opcodes.
    pub is_syscall: T,

    /// Memory Instructions.
    pub is_lb: T,
    pub is_lbu: T,
    pub is_lh: T,
    pub is_lhu: T,
    pub is_lw: T,
    pub is_lwl: T,
    pub is_lwr: T,
    pub is_ll: T,
    pub is_sb: T,
    pub is_sh: T,
    pub is_sw: T,
    pub is_swl: T,
    pub is_swr: T,
    pub is_sc: T,
    // pub is_sdc1: T,

    /// Miscellaneous.
    pub is_unimpl: T,
}

impl<F: PrimeField> OpcodeSelectorCols<F> {
    pub fn populate(&mut self, instruction: &Instruction) {
        self.has_hi = F::from_bool(instruction.opcode.is_use_lo_hi_alu());
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);

        if instruction.is_alu_instruction() {
            self.is_alu = F::ONE;
        } else if instruction.is_syscall_instruction() {
            self.is_syscall = F::ONE;
        } else if instruction.is_memory_instruction() {
            match instruction.opcode {
                Opcode::LB => self.is_lb = F::ONE,
                Opcode::LBU => self.is_lbu = F::ONE,
                Opcode::LHU => self.is_lhu = F::ONE,
                Opcode::LH => self.is_lh = F::ONE,
                Opcode::LW => self.is_lw = F::ONE,
                Opcode::LWL => self.is_lwl = F::ONE,
                Opcode::LWR => self.is_lwr = F::ONE,
                Opcode::LL => self.is_ll = F::ONE,
                Opcode::SB => self.is_sb = F::ONE,
                Opcode::SH => self.is_sh = F::ONE,
                Opcode::SW => self.is_sw = F::ONE,
                Opcode::SWL => self.is_swl = F::ONE,
                Opcode::SWR => self.is_swr = F::ONE,
                Opcode::SC => self.is_sc = F::ONE,
                // Opcode::SDC1 => self.is_sdc1 = F::ONE,
                _ => unreachable!(),
            }
        }
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let columns = vec![
            self.has_hi,
            self.imm_b,
            self.imm_c,
            self.is_alu,
            self.is_syscall,
            self.is_lb,
            self.is_lbu,
            self.is_lh,
            self.is_lhu,
            self.is_lw,
            self.is_lwl,
            self.is_lwr,
            self.is_ll,
            self.is_sb,
            self.is_sh,
            self.is_sw,
            self.is_swl,
            self.is_swr,
            self.is_sc,
            // self.is_sdc1,
            self.is_unimpl,
        ];
        assert_eq!(columns.len(), NUM_OPCODE_SELECTOR_COLS);
        columns.into_iter()
    }
}
