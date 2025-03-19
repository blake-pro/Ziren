#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Keccak256 rate Xor operation between the given state and input block.
///
/// ### Safety
///
/// The caller must ensure that `state` and `block` are valid pointers to data that are aligned along
/// a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_keccak256_xor(
    state: *mut [u64; 25],
    block: *mut [u32; 34],
) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "syscall",
        in("$2") crate::syscalls::KECCAK256_XOR,
        in("$4") state,
        in("$5") block
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}



