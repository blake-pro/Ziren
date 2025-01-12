//! Syscall definitions & implementations for the [`crate::Executor`].

mod code;
mod context;

mod halt;
mod hint;
mod stdsys;
mod verify;
mod write;

use std::sync::Arc;

use halt::HaltSyscall;
use hashbrown::HashMap;
use stdsys::*;

pub use code::*;
pub use context::*;
use hint::{HintLenSyscall, HintReadSyscall};
use verify::VerifySyscall;
use write::WriteSyscall;

/// A system call in the SP1 RISC-V zkVM.
///
/// This trait implements methods needed to execute a system call inside the [`crate::Executor`].
pub trait Syscall: Send + Sync {
    /// Executes the syscall.
    ///
    /// Returns the resulting value of register a0. `arg1` and `arg2` are the values in registers
    /// A0 and A1, respectively. While not a hard requirement, the convention is that the return
    /// value is only for system calls such as `HALT`. Most precompiles use `arg1` and `arg2` to
    /// denote the addresses of the input data, and write the result to the memory at `arg1`.
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<(u32, u32)>;

    /// The number of extra cycles that the syscall takes to execute.
    ///
    /// Unless this syscall is complex and requires many cycles, this should be zero.
    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

/// Creates the default syscall map.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn default_syscall_map() -> HashMap<SyscallCode, Arc<dyn Syscall>> {
    let mut syscall_map = HashMap::<SyscallCode, Arc<dyn Syscall>>::default();

    syscall_map.insert(SyscallCode::SYSEXITGROUP, Arc::new(HaltSyscall));

    syscall_map.insert(SyscallCode::SYSHINTLEN, Arc::new(HintLenSyscall));

    syscall_map.insert(SyscallCode::SYSHINTREAD, Arc::new(HintReadSyscall));

    syscall_map.insert(SyscallCode::SYSMMAP, Arc::new(MmapSyscall));
    syscall_map.insert(SyscallCode::SYSMMAP2, Arc::new(MmapSyscall));
    syscall_map.insert(SyscallCode::SYSCLONE, Arc::new(CloneSyscall));
    syscall_map.insert(SyscallCode::SYSBRK, Arc::new(BrkSyscall));

    syscall_map.insert(SyscallCode::SYSREAD, Arc::new(ReadSyscall));
    syscall_map.insert(SyscallCode::SYSWRITE, Arc::new(WriteSyscall));
    syscall_map.insert(SyscallCode::SYSFCNTL, Arc::new(FcntlSyscall));
    syscall_map.insert(
        SyscallCode::SYSSETTHREADAREA,
        Arc::new(SetThreadAreaSyscall),
    );

    syscall_map.insert(SyscallCode::SYSVERIFY, Arc::new(VerifySyscall));

    syscall_map
}
