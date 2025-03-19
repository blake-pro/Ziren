use std::mem::size_of;
use p3_keccak_air::KeccakCols;
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;

use crate::{
    memory::MemoryReadWriteCols,
    operations::{
        Add5Operation, AddOperation, AndOperation, FixedRotateRightOperation, NotOperation,
        XorOperation,
    },
};
use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::syscall::precompiles::keccak256::permute::columns::NUM_KECCAK_MEM_COLS;
use crate::syscall::precompiles::keccak256::STATE_NUM_WORDS;

pub const NUM_KECCAK256_XOR_COLS: usize = size_of::<Keccak256XorCols<u8>>();
pub const RATE_SIZE_U32S: usize = 34;
pub const NUM_KECCAK256_XOR_ROUNDS: usize = 1;

/// A set of columns needed to compute the Keccak256 Xor function.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Keccak256XorCols<T> {
    pub shard: T,
    pub clk: T,
    pub rate_addr: T,
    pub block_addr: T,

    /// Memory columns for reading the rate.
    pub original_rate_mem: [MemoryReadCols<T>; RATE_SIZE_U32S],

    /// Memory columns for the block.
    pub block_mem: [MemoryReadCols<T>; RATE_SIZE_U32S],

    /// Memory columns for writing the xored rate.
    pub xored_rate_mem: [MemoryWriteCols<T>; RATE_SIZE_U32S],

    /// The xored rate values.
    pub xored_rate: [XorOperation<T>; RATE_SIZE_U32S],

    pub is_real: T,
}