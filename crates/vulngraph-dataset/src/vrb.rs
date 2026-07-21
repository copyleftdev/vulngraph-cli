//! VRB1: compiled version-range store.
//!
//! `version_ranges.json` in a release is ~38 MB of nested JSON; parsing it
//! per invocation would cost ~500 ms. Mirroring kilo's compile-at-update
//! precedent, `update` compiles it once into this compact binary keyed by
//! `fnv1a(ecosystem:name)`. The file lives at `compiled/version_ranges.bin`
//! beside the untouched db dir, so the release's 12-file `snapshot_id`
//! contract is undisturbed; the compiled file's own sha256 is pinned in
//! `installed-manifest.json`.
//!
//! Layout (little-endian, all structs `#[repr(C)]` + Pod, size-asserted):
//!
//! ```text
//! Header  40 B: magic [u8;8]=b"VGVRB1\0\0", format u32=1,
//!               bucket_cnt u32 (pow2), entry_cnt u32, range_cnt u32,
//!               blob_len u64, reserved u64=0
//! Slots:  bucket_cnt x VrSlot  (16 B: hash u64, entry u32, _pad u32)
//! Entries: entry_cnt x VrEntry (16 B: key_off u32, range_start u32,
//!                               range_len u32, key_len u16, _pad u16)
//! Ranges: range_cnt x VrRange  (20 B: cve_node u32, intro_off u32,
//!                               fixed_off u32, intro_len u16, fixed_len u16,
//!                               flags u32 bit0=HAS_FIXED)
//! Blob:   blob_len raw UTF-8 (deduplicated keys + version strings)
//! ```
//!
//! The slot table follows the engine's `idx_extid.bin` contract (fnv1a,
//! hash 0 -> 1 substitution, power-of-2 capacity at <= 0.7 load, linear
//! probing) **plus** key-byte verification through the entry, so hash
//! collisions cannot corrupt lookups. Version strings are stored verbatim
//! and compared with the vendored `semver` module at query time.

use crate::engine::graph::Graph;
use crate::engine::types::fnv1a_hash;
use crate::{DatasetError, Result};
use bytemuck::{Pod, Zeroable};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;

pub const VRB_MAGIC: [u8; 8] = *b"VGVRB1\0\0";
pub const VRB_FORMAT: u32 = 1;
const HEADER_LEN: usize = 40;
const MAX_VRB_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct VrSlot {
    hash: u64,
    entry: u32,
    _pad: u32,
}
const _: () = assert!(size_of::<VrSlot>() == 16);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct VrEntry {
    key_off: u32,
    range_start: u32,
    range_len: u32,
    key_len: u16,
    _pad: u16,
}
const _: () = assert!(size_of::<VrEntry>() == 16);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct VrRange {
    pub cve_node: u32,
    intro_off: u32,
    fixed_off: u32,
    intro_len: u16,
    fixed_len: u16,
    flags: u32,
}
const _: () = assert!(size_of::<VrRange>() == 20);

const FLAG_HAS_FIXED: u32 = 1;

/// Raw JSON shape of `version_ranges.json`:
/// package -> cve -> [(introduced, fixed)]
pub type VersionRangesJson = HashMap<String, HashMap<String, Vec<(String, Option<String>)>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileStats {
    pub packages: usize,
    pub ranges: usize,
    /// Ranges dropped because their CVE is absent from the graph.
    pub dropped_range_cves: usize,
}

/// Deduplicating string-blob builder.
struct BlobBuilder {
    bytes: Vec<u8>,
    seen: HashMap<String, u32>,
}

impl BlobBuilder {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            seen: HashMap::new(),
        }
    }

    fn intern(&mut self, s: &str) -> Result<(u32, u16)> {
        let len = u16::try_from(s.len())
            .map_err(|_| DatasetError::Invalid(format!("string too long for VRB blob: {s:?}")))?;
        if let Some(&off) = self.seen.get(s) {
            return Ok((off, len));
        }
        let off = u32::try_from(self.bytes.len())
            .map_err(|_| DatasetError::Invalid("VRB blob exceeds u32 offsets".to_string()))?;
        self.bytes.extend_from_slice(s.as_bytes());
        self.seen.insert(s.to_string(), off);
        Ok((off, len))
    }
}

/// Compile `version_ranges.json` into a VRB1 file. Deterministic: identical
/// input JSON and graph produce byte-identical output.
///
/// # Errors
/// Fails on unreadable/malformed input, oversized output, or I/O errors.
pub fn compile(json_path: &Path, graph: &Graph, out_path: &Path) -> Result<CompileStats> {
    let raw = std::fs::read(json_path)?;
    let parsed: VersionRangesJson = serde_json::from_slice(&raw)?;
    drop(raw);

    // Deterministic ordering: BTreeMap over packages, then CVE id, then range.
    let sorted: BTreeMap<&String, BTreeMap<&String, &Vec<(String, Option<String>)>>> = parsed
        .iter()
        .map(|(pkg, cves)| (pkg, cves.iter().collect()))
        .collect();

    let mut blob = BlobBuilder::new();
    let mut entries: Vec<VrEntry> = Vec::new();
    let mut ranges: Vec<VrRange> = Vec::new();
    let mut hashes: Vec<u64> = Vec::new();
    let mut dropped = 0usize;

    for (pkg, cves) in &sorted {
        let range_start = u32::try_from(ranges.len())
            .map_err(|_| DatasetError::Invalid("VRB range count exceeds u32".to_string()))?;
        for (cve_id, cve_ranges) in cves {
            let Some((node_id, _)) = graph.node_by_id(cve_id) else {
                dropped += cve_ranges.len();
                continue;
            };
            let mut sorted_ranges: Vec<&(String, Option<String>)> = cve_ranges.iter().collect();
            sorted_ranges.sort();
            for (introduced, fixed) in sorted_ranges {
                let (intro_off, intro_len) = blob.intern(introduced)?;
                let (fixed_off, fixed_len, flags) = match fixed {
                    Some(f) => {
                        let (off, len) = blob.intern(f)?;
                        (off, len, FLAG_HAS_FIXED)
                    }
                    None => (0, 0, 0),
                };
                ranges.push(VrRange {
                    cve_node: node_id.0,
                    intro_off,
                    fixed_off,
                    intro_len,
                    fixed_len,
                    flags,
                });
            }
        }
        let range_len = u32::try_from(ranges.len()).unwrap_or(u32::MAX) - range_start;
        if range_len == 0 {
            continue; // every CVE for this package was dropped
        }
        let (key_off, key_len) = blob.intern(pkg)?;
        let mut hash = fnv1a_hash(pkg.as_bytes());
        if hash == 0 {
            hash = 1;
        }
        hashes.push(hash);
        entries.push(VrEntry {
            key_off,
            range_start,
            range_len,
            key_len,
            _pad: 0,
        });
    }

    // Slot table: power of 2 at <= 0.7 load, same contract as idx_extid.bin.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let min_cap = ((entries.len() as f64 / 0.7).ceil() as usize).max(16);
    let bucket_cnt = min_cap.next_power_of_two();
    let mask = bucket_cnt - 1;
    let mut slots = vec![VrSlot::zeroed(); bucket_cnt];
    for (i, &hash) in hashes.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let mut pos = (hash as usize) & mask;
        loop {
            if slots[pos].hash == 0 {
                #[allow(clippy::cast_possible_truncation)]
                let entry = i as u32;
                slots[pos] = VrSlot {
                    hash,
                    entry,
                    _pad: 0,
                };
                break;
            }
            pos = (pos + 1) & mask;
        }
    }

    // Serialize.
    let mut out: Vec<u8> = Vec::with_capacity(
        HEADER_LEN + slots.len() * 16 + entries.len() * 16 + ranges.len() * 20 + blob.bytes.len(),
    );
    out.extend_from_slice(&VRB_MAGIC);
    out.extend_from_slice(&VRB_FORMAT.to_le_bytes());
    out.extend_from_slice(&u32::try_from(bucket_cnt).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&u32::try_from(entries.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&u32::try_from(ranges.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&(blob.bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(bytemuck::cast_slice(&slots));
    out.extend_from_slice(bytemuck::cast_slice(&entries));
    out.extend_from_slice(bytemuck::cast_slice(&ranges));
    out.extend_from_slice(&blob.bytes);

    if out.len() as u64 > MAX_VRB_BYTES {
        return Err(DatasetError::Invalid(format!(
            "compiled VRB is {} bytes, exceeding the {MAX_VRB_BYTES}-byte cap",
            out.len()
        )));
    }

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, &out)?;
    Ok(CompileStats {
        packages: entries.len(),
        ranges: ranges.len(),
        dropped_range_cves: dropped,
    })
}

/// Read-side view of a VRB1 file. The file is treated as untrusted: the
/// header, section extents, and every offset are validated before use.
pub struct VrbReader {
    slots: Vec<VrSlot>,
    entries: Vec<VrEntry>,
    ranges: Vec<VrRange>,
    blob: Vec<u8>,
}

fn read_section<T: Pod + Zeroable>(bytes: &[u8], offset: usize, count: usize) -> Result<Vec<T>> {
    let size = count
        .checked_mul(size_of::<T>())
        .ok_or_else(|| DatasetError::Invalid("VRB section size overflow".to_string()))?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| DatasetError::Invalid("VRB section extent overflow".to_string()))?;
    if end > bytes.len() {
        return Err(DatasetError::Invalid(
            "VRB section exceeds file".to_string(),
        ));
    }
    let mut out = vec![T::zeroed(); count];
    bytemuck::cast_slice_mut::<T, u8>(&mut out).copy_from_slice(&bytes[offset..end]);
    Ok(out)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

impl VrbReader {
    /// Open and fully validate a VRB1 file.
    ///
    /// # Errors
    /// Fails on any structural violation: bad magic/format, non-power-of-2
    /// bucket count, section extents beyond the file, or any entry/range
    /// offset outside the blob. This is the `vrb_open` fuzz entry point.
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// # Errors
    /// See [`VrbReader::open`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let invalid = |msg: &str| DatasetError::Invalid(format!("VRB: {msg}"));
        if bytes.len() < HEADER_LEN {
            return Err(invalid("file shorter than header"));
        }
        if bytes[..8] != VRB_MAGIC {
            return Err(invalid("bad magic"));
        }
        if read_u32(bytes, 8) != VRB_FORMAT {
            return Err(invalid("unsupported format version"));
        }
        let bucket_cnt = read_u32(bytes, 12) as usize;
        let entry_cnt = read_u32(bytes, 16) as usize;
        let range_cnt = read_u32(bytes, 20) as usize;
        let mut blob_len_buf = [0u8; 8];
        blob_len_buf.copy_from_slice(&bytes[24..32]);
        let blob_len = usize::try_from(u64::from_le_bytes(blob_len_buf))
            .map_err(|_| invalid("blob length overflow"))?;

        if bucket_cnt == 0 || bucket_cnt & (bucket_cnt - 1) != 0 {
            return Err(invalid("bucket count not a power of 2"));
        }
        if entry_cnt > bucket_cnt {
            return Err(invalid("more entries than buckets"));
        }

        let slots_off = HEADER_LEN;
        let entries_off = slots_off + bucket_cnt * size_of::<VrSlot>();
        let ranges_off = entries_off + entry_cnt * size_of::<VrEntry>();
        let blob_off = ranges_off + range_cnt * size_of::<VrRange>();

        let slots: Vec<VrSlot> = read_section(bytes, slots_off, bucket_cnt)?;
        let entries: Vec<VrEntry> = read_section(bytes, entries_off, entry_cnt)?;
        let ranges: Vec<VrRange> = read_section(bytes, ranges_off, range_cnt)?;
        let blob_end = blob_off
            .checked_add(blob_len)
            .ok_or_else(|| invalid("blob extent overflow"))?;
        if blob_end != bytes.len() {
            return Err(invalid("file length does not match declared sections"));
        }
        let blob = bytes[blob_off..blob_end].to_vec();

        // Validate every reference before any query can dereference it.
        for slot in &slots {
            if slot.hash != 0 && slot.entry as usize >= entries.len() {
                return Err(invalid("slot references entry out of range"));
            }
        }
        for entry in &entries {
            let key_end = entry.key_off as usize + entry.key_len as usize;
            if key_end > blob.len() {
                return Err(invalid("entry key outside blob"));
            }
            if std::str::from_utf8(&blob[entry.key_off as usize..key_end]).is_err() {
                return Err(invalid("entry key not UTF-8"));
            }
            let range_end = entry.range_start as usize + entry.range_len as usize;
            if range_end > ranges.len() {
                return Err(invalid("entry ranges outside range section"));
            }
        }
        for range in &ranges {
            let intro_end = range.intro_off as usize + range.intro_len as usize;
            if intro_end > blob.len()
                || std::str::from_utf8(&blob[range.intro_off as usize..intro_end]).is_err()
            {
                return Err(invalid("range introduced-version outside blob"));
            }
            if range.flags & FLAG_HAS_FIXED != 0 {
                let fixed_end = range.fixed_off as usize + range.fixed_len as usize;
                if fixed_end > blob.len()
                    || std::str::from_utf8(&blob[range.fixed_off as usize..fixed_end]).is_err()
                {
                    return Err(invalid("range fixed-version outside blob"));
                }
            }
        }

        Ok(Self {
            slots,
            entries,
            ranges,
            blob,
        })
    }

    fn blob_str(&self, off: u32, len: u16) -> &str {
        // Bounds and UTF-8 validated at open.
        std::str::from_utf8(&self.blob[off as usize..off as usize + len as usize])
            .unwrap_or_default()
    }

    /// Ranges for a package key (`ecosystem:name`), or `None` when absent.
    #[must_use]
    pub fn lookup(&self, package_key: &str) -> Option<&[VrRange]> {
        let mut hash = fnv1a_hash(package_key.as_bytes());
        if hash == 0 {
            hash = 1;
        }
        let mask = self.slots.len() - 1;
        #[allow(clippy::cast_possible_truncation)]
        let mut pos = (hash as usize) & mask;
        for _ in 0..self.slots.len() {
            let slot = &self.slots[pos];
            if slot.hash == 0 {
                return None;
            }
            if slot.hash == hash {
                let entry = &self.entries[slot.entry as usize];
                // Key-byte verification: collisions cannot corrupt lookups.
                if self.blob_str(entry.key_off, entry.key_len) == package_key {
                    let start = entry.range_start as usize;
                    return Some(&self.ranges[start..start + entry.range_len as usize]);
                }
            }
            pos = (pos + 1) & mask;
        }
        None
    }

    /// Materialize a range's (introduced, fixed) version strings.
    #[must_use]
    pub fn range_versions(&self, range: &VrRange) -> (String, Option<String>) {
        let introduced = self.blob_str(range.intro_off, range.intro_len).to_string();
        let fixed = if range.flags & FLAG_HAS_FIXED != 0 {
            Some(self.blob_str(range.fixed_off, range.fixed_len).to_string())
        } else {
            None
        };
        (introduced, fixed)
    }

    #[must_use]
    pub fn package_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::testutil::FixtureDb;

    fn fixture() -> (tempfile::TempDir, Graph) {
        let dir = tempfile::tempdir().unwrap();
        let mut fx = FixtureDb::new();
        fx.add_node("CVE-2020-8203", crate::engine::types::NodeType::CVE);
        fx.add_node("CVE-2021-23337", crate::engine::types::NodeType::CVE);
        fx.add_node("npm:lodash", crate::engine::types::NodeType::PACKAGE);
        fx.write(dir.path()).unwrap();
        let graph = Graph::open(dir.path()).unwrap();
        (dir, graph)
    }

    fn sample_json() -> serde_json::Value {
        serde_json::json!({
            "npm:lodash": {
                "CVE-2020-8203": [["3.7.0", "4.17.19"]],
                "CVE-2021-23337": [["0", "4.17.21"]],
                "CVE-9999-0001": [["0", null]]
            },
            "npm:ghost-pkg": {
                "CVE-9999-0002": [["1.0.0", null]]
            }
        })
    }

    #[test]
    fn compile_lookup_round_trip() {
        let (dir, graph) = fixture();
        let json_path = dir.path().join("version_ranges.json");
        std::fs::write(&json_path, serde_json::to_vec(&sample_json()).unwrap()).unwrap();
        let out = dir.path().join("compiled/version_ranges.bin");

        let stats = compile(&json_path, &graph, &out).unwrap();
        // ghost-pkg's only CVE is absent from the graph -> whole package dropped
        assert_eq!(stats.packages, 1);
        assert_eq!(stats.ranges, 2);
        assert_eq!(stats.dropped_range_cves, 2);

        let reader = VrbReader::open(&out).unwrap();
        assert!(reader.lookup("npm:ghost-pkg").is_none());
        assert!(reader.lookup("npm:absent").is_none());
        let ranges = reader.lookup("npm:lodash").unwrap();
        assert_eq!(ranges.len(), 2);
        let versions: Vec<_> = ranges.iter().map(|r| reader.range_versions(r)).collect();
        assert!(versions.contains(&("3.7.0".to_string(), Some("4.17.19".to_string()))));
        assert!(versions.contains(&("0".to_string(), Some("4.17.21".to_string()))));
    }

    #[test]
    fn compile_is_deterministic() {
        let (dir, graph) = fixture();
        let json_path = dir.path().join("version_ranges.json");
        std::fs::write(&json_path, serde_json::to_vec(&sample_json()).unwrap()).unwrap();
        let out1 = dir.path().join("a.bin");
        let out2 = dir.path().join("b.bin");
        compile(&json_path, &graph, &out1).unwrap();
        compile(&json_path, &graph, &out2).unwrap();
        assert_eq!(std::fs::read(&out1).unwrap(), std::fs::read(&out2).unwrap());
    }

    #[test]
    fn hostile_bytes_never_panic() {
        // Truncations, flipped bytes, and garbage must all error cleanly.
        let (dir, graph) = fixture();
        let json_path = dir.path().join("version_ranges.json");
        std::fs::write(&json_path, serde_json::to_vec(&sample_json()).unwrap()).unwrap();
        let out = dir.path().join("v.bin");
        compile(&json_path, &graph, &out).unwrap();
        let good = std::fs::read(&out).unwrap();

        assert!(VrbReader::from_bytes(&[]).is_err());
        assert!(VrbReader::from_bytes(b"VGVRB1\0\0").is_err());
        for cut in [1, HEADER_LEN, good.len() - 1] {
            assert!(
                VrbReader::from_bytes(&good[..cut]).is_err(),
                "truncated at {cut}"
            );
        }
        for i in (8..good.len().min(200)).step_by(7) {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = VrbReader::from_bytes(&bad); // may fail or succeed, must not panic
        }
    }
}
