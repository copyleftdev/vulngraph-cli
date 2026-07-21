//! Primary index: external ID → NodeId hash map — read path only.
//!
//! SYNC: keep in sync with the private vulngraph repo, `engine/src/index.rs`
//! (read half: `IndexSlot`, `HashIndex`; the builder is intentionally not
//! vendored). The probe uses a checked `get` instead of upstream's
//! `get_unchecked` so `unsafe` stays confined to storage.rs.
//!
//! On-disk format: open-addressing hash table with linear probing.
//! Capacity is a power of 2; hash 0 marks an empty slot (fnv1a output 0 is
//! substituted with 1 at build time).

use super::error::{EngineError, Result};
use super::storage::MappedArray;
use super::types::{NodeId, fnv1a_hash};
use bytemuck::{Pod, Zeroable};
use std::path::Path;

/// A single slot in the hash table, mmap'd directly.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct IndexSlot {
    /// FNV-1a hash of the external ID string. 0 = empty slot.
    pub hash: u64,
    /// Internal node ID. Only valid when hash != 0.
    pub node_id: u32,
    /// Padding for alignment (u64 forces 8-byte alignment → 16 bytes total).
    pub _pad: u32,
}

const _: () = assert!(size_of::<IndexSlot>() == 16);

impl IndexSlot {
    #[inline]
    fn is_empty(&self) -> bool {
        self.hash == 0
    }
}

/// Read-only hash index backed by a memory-mapped file.
pub struct HashIndex {
    slots: MappedArray<IndexSlot>,
    capacity: usize,
}

impl HashIndex {
    /// Open an existing hash index file.
    ///
    /// # Errors
    /// Fails when the file cannot be mapped, is empty, or its slot count is
    /// not a power of two.
    pub fn open(path: &Path) -> Result<Self> {
        let slots = MappedArray::<IndexSlot>::open(path)?;
        let capacity = slots.len();
        if capacity == 0 {
            return Err(EngineError::Index("empty index file".into()));
        }
        // Capacity must be a power of 2 for fast modulo
        if capacity & (capacity - 1) != 0 {
            return Err(EngineError::Index(format!(
                "index capacity {capacity} is not a power of 2"
            )));
        }
        Ok(Self { slots, capacity })
    }

    /// Look up a node ID by external ID string.
    #[inline]
    #[must_use]
    pub fn get(&self, external_id: &str) -> Option<NodeId> {
        let hash = fnv1a_hash(external_id.as_bytes());
        self.get_by_hash(hash)
    }

    /// Look up a node ID by pre-computed hash.
    #[inline]
    #[must_use]
    pub fn get_by_hash(&self, hash: u64) -> Option<NodeId> {
        // Hash 0 is reserved for empty slots; if we ever get it, use 1 instead.
        let hash = if hash == 0 { 1 } else { hash };
        let mask = self.capacity - 1;
        #[allow(clippy::cast_possible_truncation)]
        let mut pos = (hash as usize) & mask;

        // Linear probing
        for _ in 0..self.capacity {
            let slot = self.slots.get(pos)?;
            if slot.is_empty() {
                return None;
            }
            if slot.hash == hash {
                return Some(NodeId(slot.node_id));
            }
            pos = (pos + 1) & mask;
        }
        None // Table full (should never happen with proper load factor)
    }

    /// Number of slots (capacity, not occupancy).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Count occupied slots (for diagnostics).
    #[must_use]
    pub fn occupancy(&self) -> usize {
        self.slots
            .as_slice()
            .iter()
            .filter(|s| !s.is_empty())
            .count()
    }
}
