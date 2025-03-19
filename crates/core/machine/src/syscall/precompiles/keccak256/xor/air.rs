use p3_air::{Air, BaseAir};
use p3_matrix::Matrix;
use zkm2_stark::{AluAirBuilder, LookupScope, SubAirBuilder, ZKMAirBuilder};
use crate::KeccakPermuteChip;
use crate::syscall::precompiles::keccak256::permute::columns::KeccakMemCols;
use super::columns::{Keccak256XorCols, NUM_KECCAK256_XOR_COLS};
use super::Keccak256XorChip;

impl<F> BaseAir<F> for Keccak256XorChip {
    fn width(&self) -> usize {
        NUM_KECCAK256_XOR_COLS
    }
}

impl<AB> Air<AB> for Keccak256XorChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let _main = builder.main();
    }
}
