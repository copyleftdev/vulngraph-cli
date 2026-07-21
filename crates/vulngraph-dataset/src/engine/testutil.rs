//! Test-only fixture builder for the binary graph format.
//!
//! Ships nothing: `#[cfg(test)]` at the module registration. This is NOT a
//! vendored writer — it is a minimal byte-level emitter that exists so the
//! vendored read path can be tested against known-good files. Layout rules
//! come from the format contract (48/32/16/8-byte records, sorted edge
//! arrays, power-of-2 index at <= 0.7 load, fnv1a hash-0 substitution).

use super::types::{DescSlot, EdgeRecord, EdgeType, NodeHeader, NodeId, NodeType, fnv1a_hash};
use bytemuck::Zeroable;
use std::path::Path;

pub struct FixtureDb {
    nodes: Vec<(String, NodeType)>,
    edges: Vec<(u32, u32, EdgeType)>,
    cvss: Vec<(u32, f32)>,
    epss: Vec<(u32, f32, f32)>,
    descriptions: Vec<(u32, String)>,
    published: Vec<(u32, u64)>,
}

impl Default for FixtureDb {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureDb {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            cvss: Vec::new(),
            epss: Vec::new(),
            descriptions: Vec::new(),
            published: Vec::new(),
        }
    }

    pub fn add_node(&mut self, external_id: &str, node_type: NodeType) -> NodeId {
        let id = u32::try_from(self.nodes.len()).expect("fixture too large");
        self.nodes.push((external_id.to_string(), node_type));
        NodeId(id)
    }

    pub fn add_edge(&mut self, source: NodeId, target: NodeId, edge_type: EdgeType) {
        self.edges.push((source.0, target.0, edge_type));
    }

    pub fn set_cvss(&mut self, node: NodeId, score: f32) {
        self.cvss.push((node.0, score));
    }

    pub fn set_epss(&mut self, node: NodeId, score: f32, percentile: f32) {
        self.epss.push((node.0, score, percentile));
    }

    pub fn set_description(&mut self, node: NodeId, text: &str) {
        self.descriptions.push((node.0, text.to_string()));
    }

    pub fn set_published(&mut self, node: NodeId, epoch_secs: u64) {
        self.published.push((node.0, epoch_secs));
    }

    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let node_count = self.nodes.len();

        // Strings + node headers
        let mut strings: Vec<u8> = Vec::new();
        let mut headers = vec![NodeHeader::zeroed(); node_count];

        // Sorted forward edges, grouped per source.
        let mut fwd = self.edges.clone();
        fwd.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.2.0.cmp(&b.2.0)).then(a.1.cmp(&b.1)));
        let mut rev = self.edges.clone();
        rev.sort_unstable_by(|a, b| a.1.cmp(&b.1).then(a.2.0.cmp(&b.2.0)).then(a.0.cmp(&b.0)));

        for (i, (ext_id, node_type)) in self.nodes.iter().enumerate() {
            let offset = u32::try_from(strings.len()).unwrap();
            strings.extend_from_slice(ext_id.as_bytes());
            let first_edge = fwd.iter().position(|e| e.0 == u32::try_from(i).unwrap());
            let edge_count = fwd
                .iter()
                .filter(|e| e.0 == u32::try_from(i).unwrap())
                .count();
            headers[i] = NodeHeader {
                node_id: u32::try_from(i).unwrap(),
                node_type: *node_type,
                _pad0: [0; 3],
                external_id_hash: fnv1a_hash(ext_id.as_bytes()),
                external_id_offset: offset,
                external_id_len: u16::try_from(ext_id.len()).unwrap(),
                _pad1: [0; 2],
                edge_list_offset: u32::try_from(first_edge.unwrap_or(0)).unwrap(),
                edge_count: u16::try_from(edge_count).unwrap(),
                _pad2: [0; 2],
                created_at: 1_700_000_000_000_000,
                updated_at: 1_700_000_000_000_000,
            };
        }

        let edge_record = |(source, target, edge_type): &(u32, u32, EdgeType)| EdgeRecord {
            source: *source,
            target: *target,
            edge_type: *edge_type,
            _pad0: [0; 3],
            properties_offset: 0,
            created_at: 1_700_000_000_000_000,
            _reserved: 0,
        };
        let fwd_records: Vec<EdgeRecord> = fwd.iter().map(edge_record).collect();
        let rev_records: Vec<EdgeRecord> = rev.iter().map(edge_record).collect();

        // Hash index: power of 2 at <= 0.7 load, linear probing.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let capacity = (((node_count as f64 / 0.7).ceil() as usize).max(16)).next_power_of_two();
        let mask = capacity - 1;
        // (hash, node_id) slots as raw 16-byte records
        let mut slots = vec![(0u64, 0u32); capacity];
        for (i, (ext_id, _)) in self.nodes.iter().enumerate() {
            let mut hash = fnv1a_hash(ext_id.as_bytes());
            if hash == 0 {
                hash = 1;
            }
            #[allow(clippy::cast_possible_truncation)]
            let mut pos = (hash as usize) & mask;
            loop {
                if slots[pos].0 == 0 {
                    slots[pos] = (hash, u32::try_from(i).unwrap());
                    break;
                }
                pos = (pos + 1) & mask;
            }
        }
        let mut idx_bytes: Vec<u8> = Vec::with_capacity(capacity * 16);
        for (hash, node_id) in &slots {
            idx_bytes.extend_from_slice(&hash.to_le_bytes());
            idx_bytes.extend_from_slice(&node_id.to_le_bytes());
            idx_bytes.extend_from_slice(&0u32.to_le_bytes());
        }

        // Property columns
        let mut cvss = vec![0f32; node_count];
        for &(n, s) in &self.cvss {
            cvss[n as usize] = s;
        }
        let mut epss = vec![0f32; node_count];
        let mut epss_pct = vec![0f32; node_count];
        for &(n, s, p) in &self.epss {
            epss[n as usize] = s;
            epss_pct[n as usize] = p;
        }
        let mut published = vec![0u64; node_count];
        for &(n, ts) in &self.published {
            published[n as usize] = ts;
        }
        let mut desc_slots = vec![DescSlot::zeroed(); node_count];
        let mut desc_strings: Vec<u8> = Vec::new();
        for (n, text) in &self.descriptions {
            desc_slots[*n as usize] = DescSlot {
                offset: u32::try_from(desc_strings.len()).unwrap(),
                len: u32::try_from(text.len()).unwrap(),
            };
            desc_strings.extend_from_slice(text.as_bytes());
        }

        std::fs::write(dir.join("nodes.bin"), bytemuck::cast_slice(&headers))?;
        std::fs::write(
            dir.join("edges_fwd.bin"),
            bytemuck::cast_slice(&fwd_records),
        )?;
        std::fs::write(
            dir.join("edges_rev.bin"),
            bytemuck::cast_slice(&rev_records),
        )?;
        std::fs::write(dir.join("strings.bin"), &strings)?;
        std::fs::write(dir.join("idx_extid.bin"), &idx_bytes)?;
        std::fs::write(dir.join("props_cvss.bin"), bytemuck::cast_slice(&cvss))?;
        std::fs::write(dir.join("props_epss.bin"), bytemuck::cast_slice(&epss))?;
        std::fs::write(
            dir.join("props_epss_pct.bin"),
            bytemuck::cast_slice(&epss_pct),
        )?;
        std::fs::write(
            dir.join("props_published.bin"),
            bytemuck::cast_slice(&published),
        )?;
        std::fs::write(
            dir.join("desc_index.bin"),
            bytemuck::cast_slice(&desc_slots),
        )?;
        std::fs::write(dir.join("desc_strings.bin"), &desc_strings)?;
        std::fs::write(
            dir.join("meta.json"),
            serde_json::json!({
                "version": 1,
                "node_count": node_count,
                "edge_count": self.edges.len(),
                "created_at": "1700000000Z",
                "updated_at": "1700000000Z",
            })
            .to_string(),
        )?;
        Ok(())
    }
}
