//! The VulnGraph — the main facade that ties together all storage layers.
//!
//! SYNC: keep in sync with the private vulngraph repo, `engine/src/graph.rs`
//! (the file is read-only upstream too; vendored verbatim apart from
//! module paths).
//!
//! Opening a graph mmap's all binary files and provides:
//! - O(1) node lookup by external ID (CVE ID, package name, etc.)
//! - O(degree) edge traversal (outgoing and incoming)
//! - O(1) property reads (EPSS, CVSS, KEV bitset)
//! - Binary search on sorted secondary indexes
// Vendored verbatim from upstream; keep the original `match` forms so the
// file stays diffable against the private engine.
#![allow(clippy::manual_let_else)]

use super::error::{EngineError, Result};
use super::index::HashIndex;
use super::storage::{MappedArray, MappedBytes};
use super::types::{DescSlot, EdgeRecord, EdgeType, NodeHeader, NodeId, NodeType};
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────
// Database metadata (on-disk JSON header)
// ─────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct GraphMeta {
    pub version: u32,
    pub node_count: u32,
    pub edge_count: u64,
    pub created_at: String,
    pub updated_at: String,
}

// ─────────────────────────────────────────────────
// The graph
// ─────────────────────────────────────────────────

pub struct Graph {
    pub meta: GraphMeta,
    base_path: PathBuf,

    // Core storage (mmap'd)
    nodes: MappedArray<NodeHeader>,
    edges_fwd: MappedArray<EdgeRecord>,
    edges_rev: MappedArray<EdgeRecord>,
    strings: MappedBytes,

    // Primary index
    extid_index: HashIndex,

    // Hot property columns (mmap'd f32 arrays, indexed by node_id)
    epss_scores: Option<MappedArray<f32>>,
    epss_percentiles: Option<MappedArray<f32>>,
    cvss_scores: Option<MappedArray<f32>>,

    // Description strings (variable-length, indexed via DescSlot)
    desc_index: Option<MappedArray<DescSlot>>,
    desc_strings: Option<MappedBytes>,

    // Publication dates (epoch seconds, indexed by node_id)
    published_at: Option<MappedArray<u64>>,
}

impl Graph {
    /// Open an existing VulnGraph database from disk.
    pub fn open(path: &Path) -> Result<Self> {
        let meta_path = path.join("meta.json");
        let meta_content = std::fs::read_to_string(&meta_path)
            .map_err(|e| EngineError::Io(format!("{}: {}", meta_path.display(), e)))?;
        let meta: GraphMeta = serde_json::from_str(&meta_content)
            .map_err(|e| EngineError::InvalidData(format!("meta.json: {}", e)))?;

        let nodes = MappedArray::<NodeHeader>::open(&path.join("nodes.bin"))?;
        let edges_fwd = MappedArray::<EdgeRecord>::open(&path.join("edges_fwd.bin"))?;
        let edges_rev = MappedArray::<EdgeRecord>::open(&path.join("edges_rev.bin"))?;
        let strings = MappedBytes::open(&path.join("strings.bin"))?;
        let extid_index = HashIndex::open(&path.join("idx_extid.bin"))?;

        // Optional property columns
        let epss_scores = MappedArray::<f32>::open(&path.join("props_epss.bin")).ok();
        let epss_percentiles = MappedArray::<f32>::open(&path.join("props_epss_pct.bin")).ok();
        let cvss_scores = MappedArray::<f32>::open(&path.join("props_cvss.bin")).ok();

        // Optional description column
        let desc_index = MappedArray::<DescSlot>::open(&path.join("desc_index.bin")).ok();
        let desc_strings = MappedBytes::open(&path.join("desc_strings.bin")).ok();

        // Optional publication dates
        let published_at = MappedArray::<u64>::open(&path.join("props_published.bin")).ok();

        Ok(Self {
            meta,
            base_path: path.to_path_buf(),
            nodes,
            edges_fwd,
            edges_rev,
            strings,
            extid_index,
            epss_scores,
            epss_percentiles,
            cvss_scores,
            desc_index,
            desc_strings,
            published_at,
        })
    }

    // ─── Node queries ───────────────────────────

    /// Number of nodes in the graph.
    #[inline]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges in the graph.
    #[inline]
    pub fn edge_count(&self) -> usize {
        self.edges_fwd.len()
    }

    /// Look up a node by external ID (e.g., "CVE-2024-4577").
    /// O(1) hash lookup.
    #[inline]
    pub fn node_by_id(&self, external_id: &str) -> Option<(NodeId, &NodeHeader)> {
        let node_id = self.extid_index.get(external_id)?;
        let header = self.nodes.get(node_id.as_usize())?;
        Some((node_id, header))
    }

    /// Get the node header by internal NodeId.
    #[inline]
    pub fn node(&self, id: NodeId) -> Option<&NodeHeader> {
        self.nodes.get(id.as_usize())
    }

    /// Resolve the external ID string for a node.
    #[inline]
    pub fn external_id(&self, header: &NodeHeader) -> Option<&str> {
        self.strings.str_at(
            header.external_id_offset as usize,
            header.external_id_len as usize,
        )
    }

    // ─── Edge queries ───────────────────────────

    /// Get all outgoing edges for a node.
    /// O(degree) — reads a contiguous slice of the sorted forward edge array.
    pub fn edges_from(&self, node_id: NodeId) -> &[EdgeRecord] {
        let header = match self.nodes.get(node_id.as_usize()) {
            Some(h) => h,
            None => return &[],
        };
        let start = header.edge_list_offset as usize;
        let count = header.edge_count as usize;
        if count == 0 {
            return &[];
        }
        let slice = self.edges_fwd.as_slice();
        if start + count <= slice.len() {
            &slice[start..start + count]
        } else {
            &[]
        }
    }

    /// Get all outgoing edges of a specific type for a node.
    pub fn edges_from_typed(&self, node_id: NodeId, edge_type: EdgeType) -> Vec<&EdgeRecord> {
        self.edges_from(node_id)
            .iter()
            .filter(|e| e.edge_type == edge_type)
            .collect()
    }

    /// Get all incoming edges for a node (uses reverse index).
    /// Binary search to find the range, then linear scan.
    pub fn edges_to(&self, node_id: NodeId) -> Vec<&EdgeRecord> {
        let rev = self.edges_rev.as_slice();
        let target = node_id.0;

        // Binary search for the first edge with this target
        let start = rev.partition_point(|e| e.target < target);
        let mut results = Vec::new();
        for edge in &rev[start..] {
            if edge.target != target {
                break;
            }
            results.push(edge);
        }
        results
    }

    /// Get incoming edges of a specific type.
    pub fn edges_to_typed(&self, node_id: NodeId, edge_type: EdgeType) -> Vec<&EdgeRecord> {
        self.edges_to(node_id)
            .into_iter()
            .filter(|e| e.edge_type == edge_type)
            .collect()
    }

    // ─── Property queries ───────────────────────

    /// Get EPSS score for a node. Returns None if not a CVE or no EPSS data.
    #[inline]
    pub fn epss_score(&self, node_id: NodeId) -> Option<f32> {
        self.epss_scores.as_ref()?.get(node_id.as_usize()).copied()
    }

    /// Get EPSS percentile for a node.
    #[inline]
    pub fn epss_percentile(&self, node_id: NodeId) -> Option<f32> {
        self.epss_percentiles
            .as_ref()?
            .get(node_id.as_usize())
            .copied()
    }

    /// Get CVSS score for a node.
    #[inline]
    pub fn cvss_score(&self, node_id: NodeId) -> Option<f32> {
        self.cvss_scores.as_ref()?.get(node_id.as_usize()).copied()
    }

    /// Get description string for a node. Returns None if no description stored.
    pub fn description(&self, node_id: NodeId) -> Option<&str> {
        let idx = self.desc_index.as_ref()?;
        let strings = self.desc_strings.as_ref()?;
        let slot = idx.get(node_id.as_usize())?;
        if slot.len == 0 {
            return None;
        }
        strings.str_at(slot.offset as usize, slot.len as usize)
    }

    /// Get publication date for a node (epoch seconds). Returns None if not set.
    #[inline]
    pub fn published_at(&self, node_id: NodeId) -> Option<u64> {
        let val = self
            .published_at
            .as_ref()?
            .get(node_id.as_usize())
            .copied()?;
        if val == 0 { None } else { Some(val) }
    }

    // ─── Composite queries ──────────────────────

    /// Full CVE lookup: header + external ID + scores + edges.
    /// This is the P0 query that must be <1ms.
    pub fn cve_lookup<'a>(&'a self, cve_id: &str) -> Option<CveLookupResult<'a>> {
        let (node_id, header) = self.node_by_id(cve_id)?;

        Some(CveLookupResult {
            node_id,
            cve_id: self.external_id(header).unwrap_or("?"),
            node_type: header.node_type,
            epss_score: self.epss_score(node_id),
            epss_percentile: self.epss_percentile(node_id),
            cvss_score: self.cvss_score(node_id),
            edges_out: self.edges_from(node_id),
            edges_in: self.edges_to(node_id),
            created_at: header.created_at,
            updated_at: header.updated_at,
        })
    }

    /// Find all CVEs affecting a package (reverse edge lookup).
    /// P1 query: given (ecosystem, package), find all CVEs via reverse `affects` edges.
    pub fn cves_for_package(&self, package_id: &str) -> Vec<NodeId> {
        let node_id = match self.extid_index.get(package_id) {
            Some(id) => id,
            None => return Vec::new(),
        };

        self.edges_to_typed(node_id, EdgeType::AFFECTS)
            .iter()
            .map(|e| NodeId(e.source))
            .collect()
    }

    /// Base path of the database on disk.
    pub fn path(&self) -> &Path {
        &self.base_path
    }
}

// ─────────────────────────────────────────────────
// Query result types
// ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct CveLookupResult<'a> {
    pub node_id: NodeId,
    pub cve_id: &'a str,
    pub node_type: NodeType,
    pub epss_score: Option<f32>,
    pub epss_percentile: Option<f32>,
    pub cvss_score: Option<f32>,
    pub edges_out: &'a [EdgeRecord],
    pub edges_in: Vec<&'a EdgeRecord>,
    pub created_at: u64,
    pub updated_at: u64,
}
