use p3_air::{Air, BaseAir};
use p3_matrix::Matrix;
use zkm2_stark::{AluAirBuilder, LookupScope, SubAirBuilder, ZKMAirBuilder};
use crate::KeccakPermuteChip;
use crate::syscall::precompiles::keccak256::permute::columns::KeccakMemCols;
use super::columns::{Keccak256XorCols, NUM_KECCAK256_XOR_COLS, RATE_SIZE_U32S};
use super::Keccak256XorChip;
use std::borrow::Borrow;
use p3_field::FieldAlgebra;
use zkm2_core_executor::syscalls::SyscallCode;
use crate::air::{MemoryAirBuilder, WordAirBuilder};
use crate::memory::MemoryCols;
use crate::operations::XorOperation;

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
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &Keccak256XorCols<AB::Var> = (*local).borrow();
        let next: &Keccak256XorCols<AB::Var> = (*next).borrow();

        let nb_bytes_in_word = AB::F::from_canonical_u32(4);

        // receive syscall
        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::KECCAK256_XOR.syscall_id()),
            local.rate_addr,
            local.block_addr,
            local.is_real,
            LookupScope::Local,
        );

        // memory
        for i in 0..RATE_SIZE_U32S {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.rate_addr + nb_bytes_in_word,
                &local.original_rate_mem[i as usize],
                local.is_real,
            );

            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.block_addr + nb_bytes_in_word,
                &local.block_mem[i as usize],
                local.is_real,
            );

            builder.eval_memory_access(
                local.shard,
                local.clk + AB::F::from_canonical_u32(1),
                local.rate_addr + nb_bytes_in_word,
                &local.xored_rate_mem[i as usize],
                local.is_real,
            )
        }

        // xor
        for i in 0..RATE_SIZE_U32S {
            XorOperation::<AB::F>::eval(
                builder,
                local.original_rate_mem[i].access.value,
                local.block_mem[i].access.value,
                local.xored_rate[i],
                local.is_real,
            );
        }

        // Range check all the values in `original_rate_mem`,  to be bytes.
        for i in 0..RATE_SIZE_U32S {
            builder.slice_range_check_u8(&local.original_rate_mem[i].value().0, local.is_real);
            builder.slice_range_check_u8(&local.block_mem[i].value().0, local.is_real);
            builder.slice_range_check_u8(&local.xored_rate_mem[i].value().0, local.is_real);
        }


    }
}
