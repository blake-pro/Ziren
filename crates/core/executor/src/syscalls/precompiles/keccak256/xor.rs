use crate::{
    events::{Keccak256XorEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) const RATE_SIZE_U32S: usize = 34;
pub(crate) struct Keccak256XorSyscall;
impl Syscall for Keccak256XorSyscall {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let start_clk = rt.clk;
        let rate_ptr = arg1;
        let block_ptr = arg2;

        let mut rate_read_records = Vec::new();
        let mut block_read_records = Vec::new();
        let mut rate_write_records = Vec::new();

        let (rate_records, original_rate) = rt.mr_slice(rate_ptr, RATE_SIZE_U32S);
        rate_read_records.extend_from_slice(&rate_records);

        let (block_records, block) = rt.mr_slice(block_ptr, RATE_SIZE_U32S);
        block_read_records.extend_from_slice(&block_records);

        let mut xored_rate = original_rate.clone();
        for i in 0..RATE_SIZE_U32S {
            xored_rate[i] ^= block[i];
        }

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        rt.clk += 1;

        let write_records = rt.mw_slice(rate_ptr, xored_rate.as_slice());
        rate_write_records.extend_from_slice(&write_records);

        // Push the Keccak xor event.
        // let shard = rt.current_shard();
        // let lookup_id = rt.syscall_lookup_id;
        // let event = PrecompileEvent::KeccakPermute(KeccakPermuteEvent {
        //     lookup_id,
        //     shard,
        //     clk: start_clk,
        //     pre_state: saved_state.as_slice().try_into().unwrap(),
        //     post_state: state.as_slice().try_into().unwrap(),
        //     state_read_records: rate_read_records,
        //     state_write_records: rate_write_records,
        //     state_addr: state_ptr,
        //     local_mem_access: rt.postprocess(),
        // });
        // let syscall_event =
        //     rt.rt.syscall_event(start_clk, syscall_code.syscall_id(), arg1, arg2);
        // rt.add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
