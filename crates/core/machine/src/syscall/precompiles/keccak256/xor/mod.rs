pub mod columns;
mod trace;
mod air;

/// Implements the Keccak256 Xor operation. The inputs to the syscall are a pointer to the 64 word
/// array State and a pointer to the 32 word array block.
#[derive(Default)]
pub struct Keccak256XorChip;

impl Keccak256XorChip {
    pub const fn new() -> Self {
        Self {}
    }
}
