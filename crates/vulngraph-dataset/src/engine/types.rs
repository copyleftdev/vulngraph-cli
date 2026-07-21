//! Core types for the VulnGraph binary graph format.
//!
//! SYNC: keep in sync with the private vulngraph repo, `engine/src/types.rs`.
//! Struct sizes (NodeHeader=48, EdgeRecord=32, DescSlot=8), the FNV-1a
//! constants, and the NodeType (0-7) / EdgeType (0-10) discriminants are the
//! binary ABI; any upstream change gates a `format_version` bump. The
//! write-side helper (`now_micros`) is intentionally not vendored.
//!
//! All types that touch disk are `#[repr(C)]` + `Pod`/`Zeroable` so they can be
//! memory-mapped directly without deserialization.

use bytemuck::{Pod, Zeroable};
use std::fmt;

// ─────────────────────────────────────────────────
// Node identity
// ─────────────────────────────────────────────────

/// Internal node identifier. Monotonically increasing, dense, zero-based.
/// Used as an array index into node headers, property columns, and edge lists.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Pod, Zeroable)]
#[repr(transparent)]
pub struct NodeId(pub u32);

impl NodeId {
    pub const INVALID: Self = Self(u32::MAX);

    #[inline]
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "N({})", self.0)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─────────────────────────────────────────────────
// Node type discriminant
// ─────────────────────────────────────────────────

/// Discriminant stored in the node header. One byte.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Pod, Zeroable)]
#[repr(transparent)]
pub struct NodeType(pub u8);

impl NodeType {
    pub const CVE: Self = Self(0);
    pub const PACKAGE: Self = Self(1);
    pub const EXPLOIT: Self = Self(2);
    pub const WEAKNESS: Self = Self(3); // CWE
    pub const TECHNIQUE: Self = Self(4); // ATT&CK
    pub const ACTOR: Self = Self(5); // ATT&CK group
    pub const SOFTWARE: Self = Self(6); // ATT&CK software
    pub const ADVISORY: Self = Self(7); // OSV/GHSA advisory ID
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Self::CVE => "CVE",
            Self::PACKAGE => "Package",
            Self::EXPLOIT => "Exploit",
            Self::WEAKNESS => "CWE",
            Self::TECHNIQUE => "Technique",
            Self::ACTOR => "Actor",
            Self::SOFTWARE => "Software",
            Self::ADVISORY => "Advisory",
            _ => "Unknown",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────
// Edge type discriminant
// ─────────────────────────────────────────────────

/// Discriminant for edge type. One byte.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Pod, Zeroable)]
#[repr(transparent)]
pub struct EdgeType(pub u8);

impl EdgeType {
    pub const AFFECTS: Self = Self(0); // CVE → Package@Version
    pub const FIXED_BY: Self = Self(1); // CVE → Package@FixVersion
    pub const EXPLOITED_IN_WILD: Self = Self(2); // CVE → (KEV signal)
    pub const HAS_POC: Self = Self(3); // CVE → Exploit
    pub const CLASSIFIED_AS: Self = Self(4); // CVE → CWE
    pub const USES_TECHNIQUE: Self = Self(5); // Exploit/Software → Technique
    pub const ATTRIBUTED_TO: Self = Self(6); // Technique → Actor
    pub const MITIGATES: Self = Self(7); // Mitigation → Technique
    pub const REFERENCES: Self = Self(8); // Advisory → CVE
    pub const DEPENDS_ON: Self = Self(9); // Package → Package
    pub const PARENT_OF: Self = Self(10); // CWE → CWE (hierarchy)
}

impl fmt::Display for EdgeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Self::AFFECTS => "affects",
            Self::FIXED_BY => "fixed_by",
            Self::EXPLOITED_IN_WILD => "exploited_in_wild",
            Self::HAS_POC => "has_poc",
            Self::CLASSIFIED_AS => "classified_as",
            Self::USES_TECHNIQUE => "uses_technique",
            Self::ATTRIBUTED_TO => "attributed_to",
            Self::MITIGATES => "mitigates",
            Self::REFERENCES => "references",
            Self::DEPENDS_ON => "depends_on",
            Self::PARENT_OF => "parent_of",
            _ => "unknown",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────
// On-disk node header (48 bytes, mmap'd)
// ─────────────────────────────────────────────────

/// Fixed-size header stored contiguously in `nodes.bin`.
/// Indexed directly by `NodeId` (node_id * 48 = byte offset).
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct NodeHeader {
    /// Internal monotonic ID (redundant with position, but useful for validation).
    pub node_id: u32,
    /// Discriminant: CVE, Package, Exploit, etc.
    pub node_type: NodeType,
    /// Padding for alignment.
    pub _pad0: [u8; 3],
    /// FNV-1a hash of the external ID string (e.g., "CVE-2024-4577").
    pub external_id_hash: u64,
    /// Byte offset into the string table for the external ID.
    pub external_id_offset: u32,
    /// Length of the external ID string in bytes.
    pub external_id_len: u16,
    /// Padding.
    pub _pad1: [u8; 2],
    /// Byte offset into the forward edge array where this node's edges start.
    pub edge_list_offset: u32,
    /// Number of outgoing edges.
    pub edge_count: u16,
    /// Padding.
    pub _pad2: [u8; 2],
    /// Creation timestamp (microseconds since Unix epoch).
    pub created_at: u64,
    /// Last modification timestamp (microseconds since Unix epoch).
    pub updated_at: u64,
}

const _: () = assert!(size_of::<NodeHeader>() == 48);

impl fmt::Debug for NodeHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeHeader")
            .field("node_id", &self.node_id)
            .field("node_type", &self.node_type)
            .field(
                "ext_id_hash",
                &format_args!("0x{:016x}", self.external_id_hash),
            )
            .field("edge_count", &self.edge_count)
            .finish()
    }
}

// ─────────────────────────────────────────────────
// On-disk edge record (32 bytes, mmap'd)
// ─────────────────────────────────────────────────

/// Fixed-size edge stored in sorted arrays (`edges_fwd.bin`, `edges_rev.bin`).
/// Forward array: sorted by `(source, edge_type, target)`.
/// Reverse array: sorted by `(target, edge_type, source)`.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct EdgeRecord {
    /// Source node.
    pub source: u32,
    /// Target node.
    pub target: u32,
    /// Edge type discriminant.
    pub edge_type: EdgeType,
    /// Padding.
    pub _pad0: [u8; 3],
    /// Byte offset into property storage for edge-level properties (0 = none).
    pub properties_offset: u32,
    /// Timestamp of edge creation (microseconds since Unix epoch).
    pub created_at: u64,
    /// Reserved for future use.
    pub _reserved: u64,
}

const _: () = assert!(size_of::<EdgeRecord>() == 32);

impl fmt::Debug for EdgeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Edge({} --{}--> {})",
            self.source, self.edge_type, self.target
        )
    }
}

// ─────────────────────────────────────────────────
// Description index slot (8 bytes, mmap'd)
// ─────────────────────────────────────────────────

/// Index entry for variable-length description strings.
/// Stored in `desc_index.bin`, indexed by `NodeId`.
/// Points into `desc_strings.bin`.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct DescSlot {
    /// Byte offset into desc_strings.bin. 0 with len=0 means no description.
    pub offset: u32,
    /// Length of the description in bytes.
    pub len: u32,
}

const _: () = assert!(size_of::<DescSlot>() == 8);

// ─────────────────────────────────────────────────
// Hashing utility
// ─────────────────────────────────────────────────

/// FNV-1a hash for external ID strings. Fast for short strings (CVE IDs are ~15 chars).
#[inline]
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_header_size() {
        assert_eq!(size_of::<NodeHeader>(), 48);
    }

    #[test]
    fn edge_record_size() {
        assert_eq!(size_of::<EdgeRecord>(), 32);
    }

    #[test]
    fn fnv1a_deterministic() {
        let h1 = fnv1a_hash(b"CVE-2024-4577");
        let h2 = fnv1a_hash(b"CVE-2024-4577");
        assert_eq!(h1, h2);
        assert_ne!(h1, fnv1a_hash(b"CVE-2024-4578"));
    }

    #[test]
    fn node_id_ordering() {
        assert!(NodeId(0) < NodeId(1));
        assert_eq!(NodeId(42).as_usize(), 42);
    }
}
