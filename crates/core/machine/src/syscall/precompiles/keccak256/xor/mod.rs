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

#[cfg(test)]
pub mod keccak256_xor_tests {
    use test_artifacts::{KECCAK256_XOR_ELF, KECCAK_PERMUTE_ELF};
    use zkm2_core_executor::{syscalls::SyscallCode, Executor, Instruction, Opcode, Program};
    use zkm2_stark::{CpuProver, ZKMCoreOpts};

    use crate::utils::{self, run_test};

    pub fn keccak256_xor_program() -> Program {
        let digest_ptr = 100;
        let block_ptr = 500;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 1, false, true)];
        for i in 0..(25 * 8) {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, digest_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::KECCAK256_XOR as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, digest_ptr, false, true),
            Instruction::new(Opcode::ADD, 5, 0, block_ptr, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
        ]);

        Program::new(instructions, 0, 0)
    }

    #[test]
    pub fn test_keccak256_xor_program_execute() {
        utils::setup_logger();
        let program = Program::from(KECCAK256_XOR_ELF).unwrap();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_keccak256_xor_prove_koalabear() {
        utils::setup_logger();

        let program = keccak256_xor_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_keccak256_xor_program_prove() {
        utils::setup_logger();
        let program = Program::from(KECCAK256_XOR_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}