use crate::syscall_poseidon2_permute;

/// Executes the Poseidon2 permutation on the given state
pub fn poseidon2_permute(state: &mut [u32; 16]) {
    unsafe {
        syscall_poseidon2_permute(state);
    }
}
