use crate::operations::AddDoubleOperation;
use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

pub const NUM_MADDSUB_COLS: usize = size_of::<MaddsubCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MaddsubCols<T> {
    /// Result value of intermediate mul operation.
    pub mul_lo: Word<T>,
    pub mul_hi: Word<T>,

    /// Hi/Lo word of addend operand.
    pub src2_lo: Word<T>,
    pub src2_hi: Word<T>,

    /// Add operations of low/high word.
    pub add_operation: AddDoubleOperation<T>,
}
