use enum_map::Enum;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use strum_macros::EnumIter;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, EnumIter, Ord, PartialOrd, Serialize, Deserialize, Enum,
)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum SyscallCode {
    // SYSGETPID = 4020,
    SYSMMAP2 = 4210,
    SYSMMAP = 4090,
    SYSBRK = 4045,
    SYSCLONE = 4120,
    SYSEXITGROUP = 4246,
    SYSREAD = 4003,
    SYSWRITE = 4004,
    SYSFCNTL = 4055,
    SYSSETTHREADAREA = 4283,
    SYSHINTLEN = 0x00_00_00_F0,
    SYSHINTREAD = 0x00_00_00_F1,
    SYSVERIFY = 0x00_00_00_F2,
}

impl SyscallCode {
    /// Create a [`SyscallCode`] from a u32.
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        match value {
            // 4020 => SyscallCode::SYSGETPID,
            4210 => SyscallCode::SYSMMAP2,
            4090 => SyscallCode::SYSMMAP,
            4045 => SyscallCode::SYSBRK,
            4120 => SyscallCode::SYSCLONE,
            4246 => SyscallCode::SYSEXITGROUP,
            4003 => SyscallCode::SYSREAD,
            4004 => SyscallCode::SYSWRITE,
            4283 => SyscallCode::SYSFCNTL,
            0x00_00_00_F0 => SyscallCode::SYSHINTLEN,
            0x00_00_00_F1 => SyscallCode::SYSHINTREAD,
            0x00_00_00_F2 => SyscallCode::SYSVERIFY,
            _ => panic!("invalid syscall number: {value}"),
        }
    }

    /// Get the system call identifier.
    #[must_use]
    pub fn syscall_id(self) -> u32 {
        (self as u32).to_le_bytes()[0].into()
    }

    /// Get whether the handler of the system call has its own table.
    #[must_use]
    pub fn should_send(self) -> u32 {
        //(self as u32).to_le_bytes()[1].into()
        0
    }

    /// Get the number of additional cycles the syscall uses.
    #[must_use]
    pub fn num_cycles(self) -> u32 {
        //(self as u32).to_le_bytes()[2].into()
        0
    }

    /// Map a syscall to another one in order to coalesce their counts.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn count_map(&self) -> Self {
        match self {
            _ => *self,
        }
    }
}

impl Display for SyscallCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
