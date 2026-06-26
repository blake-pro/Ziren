use zkm_derive::AlignedBorrow;

use crate::chips::{
    mem::MemoryAccessColsChips,
    poseidon2_skinny::{NUM_ROUND_CONSTANTS, WIDTH},
};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundCountersPreprocessedCols<T: Copy> {
    pub is_input_round: T,
    pub is_external_round: T,
    pub is_internal_round: T,
    pub round_constants: [T; NUM_ROUND_CONSTANTS],
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedColsSkinny<T: Copy> {
    pub memory_preprocessed: [MemoryAccessColsChips<T>; WIDTH],
    pub round_counters_preprocessed: RoundCountersPreprocessedCols<T>,
}

pub type Poseidon2PreprocessedCols<T> = Poseidon2PreprocessedColsSkinny<T>;
