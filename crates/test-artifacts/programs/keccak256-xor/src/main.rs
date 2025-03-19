#![no_std]
#![no_main]
zkm2_zkvm::entrypoint!(main);
use zkm2_zkvm::syscalls::syscall_keccak256_xor;
pub fn main() {
    for _ in 0..25 {
        let mut state = [1u64; 25];
        let mut block = [2u32; 34];
        syscall_keccak256_xor(&mut state, &mut block);
    }
}
