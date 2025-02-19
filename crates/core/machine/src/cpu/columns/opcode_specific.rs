use crate::cpu::columns::MemoryColumns;
use std::{
    fmt::{Debug, Formatter},
    mem::{size_of, transmute},
};

use static_assertions::const_assert;

use super::syscall::SyscallCols;

pub const NUM_OPCODE_SPECIFIC_COLS: usize = size_of::<OpcodeSpecificCols<u8>>();

/// Shared columns whose interpretation depends on the instruction being executed.
#[derive(Clone, Copy)]
#[repr(C)]
pub union OpcodeSpecificCols<T: Copy> {
    memory: MemoryColumns<T>,
    syscall: SyscallCols<T>,
}

impl<T: Copy + Default> Default for OpcodeSpecificCols<T> {
    fn default() -> Self {
        // We must use the largest field to avoid uninitialized padding bytes.
        const_assert!(size_of::<MemoryColumns<u8>>() == size_of::<OpcodeSpecificCols<u8>>());

        OpcodeSpecificCols { memory: MemoryColumns::default() }
    }
}

impl<T: Copy + Debug> Debug for OpcodeSpecificCols<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // SAFETY: repr(C) ensures uniform fields are in declaration order with no padding.
        let self_arr: &[T; NUM_OPCODE_SPECIFIC_COLS] = unsafe { transmute(self) };
        Debug::fmt(self_arr, f)
    }
}

// SAFETY: Each view is a valid interpretation of the underlying array.
impl<T: Copy> OpcodeSpecificCols<T> {
    pub fn memory(&self) -> &MemoryColumns<T> {
        unsafe { &self.memory }
    }
    pub fn memory_mut(&mut self) -> &mut MemoryColumns<T> {
        unsafe { &mut self.memory }
    }
    pub fn syscall(&self) -> &SyscallCols<T> {
        unsafe { &self.syscall }
    }
    pub fn syscall_mut(&mut self) -> &mut SyscallCols<T> {
        unsafe { &mut self.syscall }
    }
}
