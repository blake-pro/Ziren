#![allow(
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::unnecessary_cast,
    clippy::cast_abs_to_unsigned,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_unwrap,
    clippy::default_constructed_unit_structs,
    clippy::box_default,
    clippy::assign_op_pattern,
    deprecated,
    incomplete_features
)]
#![warn(unused_extern_crates)]

pub mod air;
pub mod alu;
pub mod bytes;
pub mod control_flow;
pub mod cpu;
pub mod global;
pub mod io;
pub mod memory;
pub mod mips;
pub mod misc;
pub mod operations;
pub mod program;
pub mod shape;
pub mod syscall;
pub mod utils;
pub use cpu::*;
pub use mips::*;

/// The global version for all components of zkMIPS.
///
/// This string should be updated whenever any step in verifying an zkMIPS proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download zkMIPS artifacts and the gnark
/// docker image.
pub const ZKM_CIRCUIT_VERSION: &str = "v1.0.0";

// Re-export the `ZKMReduceProof` struct from zkm_core_machine.
//
// This is done to avoid a circular dependency between zkm_core_machine and zkm_core_executor, and
// enable crates that depend on zkm_core_machine to import the `ZKMReduceProof` type directly.
pub mod reduce {
    pub use zkm_core_executor::ZKMReduceProof;
}

#[allow(dead_code)]
#[allow(missing_docs)]
#[cfg(test)]
pub mod programs {
    use zkm_core_executor::{Instruction, Opcode, Program};

    use test_artifacts::{FIBONACCI_ELF, HELLO_WORLD_ELF, KECCAK_SPONGE_ELF, SHA3_CHAIN_ELF};

    #[must_use]
    pub fn simple_program() -> Program {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        Program::new(instructions, 0, 0)
    }

    /// Get the fibonacci program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[must_use]
    pub fn fibonacci_program() -> Program {
        Program::from(FIBONACCI_ELF).unwrap()
    }

    /// Get the hello world program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[must_use]
    pub fn hello_world_program() -> Program {
        Program::from(HELLO_WORLD_ELF).unwrap()
    }

    /// Get the sha3-chain program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[must_use]
    pub fn sha3_chain_program() -> Program {
        Program::from(SHA3_CHAIN_ELF).unwrap()
    }

    /// Get the SSZ withdrawals program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[must_use]
    pub fn ssz_withdrawals_program() -> Program {
        Program::from(KECCAK_SPONGE_ELF).unwrap()
    }

    #[must_use]
    #[allow(clippy::unreadable_literal)]
    pub fn simple_memory_program() -> Program {
        //
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0x12348765, false, true),
            // SW and LW
            Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LW, 28, 0, 0x27654320, false, true),
            // LBU
            Instruction::new(Opcode::LBU, 27, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LBU, 26, 0, 0x27654321, false, true),
            Instruction::new(Opcode::LBU, 25, 0, 0x27654322, false, true),
            Instruction::new(Opcode::LBU, 24, 0, 0x27654323, false, true),
            // LB
            Instruction::new(Opcode::LB, 23, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LB, 22, 0, 0x27654321, false, true),
            // LHU
            Instruction::new(Opcode::LHU, 21, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LHU, 20, 0, 0x27654322, false, true),
            // LH:
            Instruction::new(Opcode::LH, 19, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LH, 18, 0, 0x27654322, false, true),
            // SB
            Instruction::new(Opcode::ADD, 17, 0, 0x38276525, false, true),
            // Save the value 0x12348765 into address 0x43627530
            Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627530, false, true),
            Instruction::new(Opcode::LW, 16, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627531, false, true),
            Instruction::new(Opcode::LW, 15, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627532, false, true),
            Instruction::new(Opcode::LW, 14, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627533, false, true),
            Instruction::new(Opcode::LW, 13, 0, 0x43627530, false, true),
            // SH
            // Save the value 0x12348765 into address 0x43627530
            Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SH, 17, 0, 0x43627530, false, true),
            Instruction::new(Opcode::LW, 12, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SH, 17, 0, 0x43627532, false, true),
            Instruction::new(Opcode::LW, 11, 0, 0x43627530, false, true),
        ];
        Program::new(instructions, 0, 0)
    }

    pub fn other_memory_program() -> Program {
        //
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, (1 << 20) + (1 << 15) + (1 << 6) - 1, false, true),
            Instruction::new(Opcode::ADD, 27, 0, 25, false, true),
            Instruction::new(
                Opcode::ADD,
                25,
                0,
                (1 << 28) + (1 << 12) + (1 << 18) - 1,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 17, 0, 0x43627530, false, true),
            Instruction::new(Opcode::ADD, 22, 0, 22, false, true),
            Instruction::new(Opcode::ADD, 10, 0, 15, false, true),
            Instruction::new(Opcode::LWR, 29, 27, 1, false, true),
            Instruction::new(Opcode::LWL, 29, 27, 1, false, true),
            Instruction::new(Opcode::LL, 29, 27, 3, false, true),
            Instruction::new(Opcode::ADD, 15, 0, (1 << 20) + (1 << 15) + (1 << 6) - 1, false, true),
            Instruction::new(Opcode::SWL, 15, 22, 2, false, true),
            Instruction::new(Opcode::SWR, 15, 22, 2, false, true),
            Instruction::new(Opcode::SWL, 26, 10, 2, false, true),
            Instruction::new(Opcode::SWR, 26, 10, 2, false, true),
            Instruction::new(Opcode::LWR, 29, 27, 0, false, true),
            Instruction::new(Opcode::LWL, 29, 27, 0, false, true),
        ];
        Program::new(instructions, 0, 0)
    }
}
