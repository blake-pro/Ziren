use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId, MemoryLocalEvent,
};

pub(crate) const RATE_SIZE_U32S: usize = 34;

/// Keccak-256 Xor Event.
///
/// This event is emitted when a keccak-256 xor operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Keccak256XorEvent {
    /// The lookup identifier.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The original rate as a list of u32 words.
    pub original_rate: Vec<u32>,
    /// The block as a list of u32 words
    pub block: Vec<u32>,
    /// The xored state as a list of u32 words.
    pub xored_rate: Vec<u32>,
    /// The memory records for the original rate.
    pub rate_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the block.
    pub block_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the xored rate.
    pub rate_write_records: Vec<MemoryWriteRecord>,
    /// The address of the rate.
    pub rate_addr: u32,
    /// The address of the block.
    pub block_addr: u32,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}