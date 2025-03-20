use std::borrow::BorrowMut;
use p3_field::PrimeField32;
use p3_keccak_air::{generate_trace_rows, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use rayon::iter::ParallelBridge;
use rayon::prelude::ParallelSlice;
use zkm2_core_executor::{ExecutionRecord, Program};
use zkm2_core_executor::events::{ByteLookupEvent, ByteRecord, Keccak256XorEvent, KeccakPermuteEvent, PrecompileEvent, SyscallEvent};
use zkm2_core_executor::syscalls::SyscallCode;
use zkm2_stark::{air::MachineAir};
use crate::syscall::precompiles::keccak256::permute::columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS};
use crate::syscall::precompiles::keccak256::xor::columns::{Keccak256XorCols, NUM_KECCAK256_XOR_COLS, NUM_KECCAK256_XOR_ROUNDS, RATE_SIZE_U32S};
use crate::utils::zeroed_f_vec;
use super::Keccak256XorChip;

impl<F: PrimeField32> MachineAir<F> for Keccak256XorChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Keccak256Xor".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::KECCAK256_XOR);
        let chunk_size = 1;

        let blu_events: Vec<Vec<ByteLookupEvent>> = events
            .par_chunks(chunk_size)
            .map(|ops: &[(SyscallEvent, PrecompileEvent)]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu = Vec::new();
                let mut chunk = zeroed_f_vec::<F>(NUM_KECCAK256_XOR_COLS * NUM_KECCAK256_XOR_ROUNDS);
                ops.iter().for_each(|(_, op)| {
                    if let PrecompileEvent::Keccak256Xor(event) = op {
                        Self::populate_chunk(event, &mut chunk, &mut blu);
                    } else {
                        unreachable!();
                    }
                });
                blu
            })
            .collect();
        for blu in blu_events {
            output.add_byte_lookup_events(blu);
        }
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = input.get_precompile_events(SyscallCode::KECCAK256_XOR);
        let num_events = events.len();
        let num_rows = std::cmp::max((num_events * NUM_KECCAK256_XOR_ROUNDS).next_power_of_two(), 8);
        tracing::info!("num rows: {:?}", num_rows);

        let chunk_size = 1;
        let values = vec![0u32; num_rows * NUM_KECCAK256_XOR_COLS];
        let mut values = unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(values) };

        let mut dummy_chunk = Vec::new();
        for _ in 0..NUM_KECCAK256_XOR_ROUNDS {
            let row = [F::ZERO; NUM_KECCAK256_XOR_COLS];
            dummy_chunk.extend_from_slice(&row);
        }

        values
            .chunks_mut(chunk_size * NUM_KECCAK256_XOR_COLS * NUM_KECCAK256_XOR_ROUNDS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_KECCAK256_XOR_ROUNDS * NUM_KECCAK256_XOR_COLS).enumerate().for_each(
                    |(j, rounds)| {
                        let idx = i * chunk_size + j;
                        if idx < num_events {
                            let mut new_byte_lookup_events = Vec::new();
                            if let PrecompileEvent::Keccak256Xor(event) = &events[idx].1 {
                                Self::populate_chunk(&event, rounds, &mut new_byte_lookup_events);
                            } else {
                                unreachable!();
                            }
                        } else {
                            rounds.copy_from_slice(&dummy_chunk[..rounds.len()]);
                        }
                    },
                );
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_KECCAK256_XOR_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::KECCAK256_XOR).is_empty()
        }
    }
}

impl Keccak256XorChip {
    pub fn populate_chunk<F: PrimeField32>(
        event: &Keccak256XorEvent,
        chunk: &mut [F],
        new_byte_lookup_events: &mut Vec<ByteLookupEvent>,
    ) {

        let start_clk = event.clk;
        let shard = event.shard;

        // Create row for the xor operation

        let row = chunk;
        let cols: &mut Keccak256XorCols<F> = row.borrow_mut();
        cols.shard = F::from_canonical_u32(shard);
        cols.clk = F::from_canonical_u32(start_clk);
        cols.rate_addr = F::from_canonical_u32(event.rate_addr);
        cols.block_addr = F::from_canonical_u32(event.block_addr);
        cols.is_real = F::ONE;

        // check the size of event features
        assert_eq!(event.original_rate.len(), RATE_SIZE_U32S);
        assert_eq!(event.block.len(), RATE_SIZE_U32S);
        assert_eq!(event.xored_rate.len(), RATE_SIZE_U32S);

        for ((j, original_value), block_value) in event.original_rate.iter().enumerate().zip(event.block.iter()) {
            cols.xored_rate[j].populate(new_byte_lookup_events, shard, *original_value, *block_value);
        }

        // Populate read memory accesses
        for (j, read_record) in event.rate_read_records.iter().enumerate() {
            cols.original_rate_mem[j].populate(*read_record, new_byte_lookup_events);
            new_byte_lookup_events
                .add_u8_range_checks(shard, &read_record.value.to_le_bytes());
        }
        for (j, read_record) in event.block_read_records.iter().enumerate() {
            cols.block_mem[j].populate(*read_record, new_byte_lookup_events);
            new_byte_lookup_events
                .add_u8_range_checks(shard, &read_record.value.to_le_bytes());
        }

        // Populate write memory accesses
        for (j, write_record) in event.rate_write_records.iter().enumerate() {
            cols.xored_rate_mem[j].populate(*write_record, new_byte_lookup_events);
            new_byte_lookup_events
                .add_u8_range_checks(shard, &write_record.value.to_le_bytes());
        }
    }
}