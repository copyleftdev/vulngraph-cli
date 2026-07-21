//! Memory-mapped binary file storage — read path only.
//!
//! SYNC: keep in sync with the private vulngraph repo, `engine/src/storage.rs`
//! (read halves: `MappedArray`, `MappedBytes`; the writer types are
//! intentionally not vendored).
//!
//! This is the only module in the workspace allowed to use `unsafe`: it is
//! confined to immutable mmaps of `Pod` data with alignment and
//! size-multiple checks at open time and a bounds-checked public API.
#![allow(unsafe_code)]

use super::error::{EngineError, Result};
use bytemuck::Pod;
use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::marker::PhantomData;
use std::path::Path;

/// A read-only memory-mapped array of `T`.
/// Zero deserialization: the mmap'd bytes ARE the array.
pub struct MappedArray<T: Pod> {
    _mmap: Mmap,
    ptr: *const T,
    len: usize,
    _marker: PhantomData<T>,
}

// SAFETY: The underlying mmap is immutable and the data is Pod (plain-old-data).
// No interior mutability, no pointers into the data that could alias.
unsafe impl<T: Pod> Send for MappedArray<T> {}
unsafe impl<T: Pod> Sync for MappedArray<T> {}

impl<T: Pod> MappedArray<T> {
    /// Open a file and memory-map it as a read-only array of `T`.
    ///
    /// # Errors
    /// Fails when the file cannot be opened or mapped, its size is not a
    /// multiple of `size_of::<T>()`, or the mapping is misaligned for `T`.
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| EngineError::Io(format!("{}: {}", path.display(), e)))?;

        let metadata = file
            .metadata()
            .map_err(|e| EngineError::Io(format!("{}: {}", path.display(), e)))?;

        let file_len = usize::try_from(metadata.len())
            .map_err(|_| EngineError::Storage(format!("{}: file too large", path.display())))?;
        let elem_size = size_of::<T>();

        if file_len == 0 {
            // Empty file: create a 1-byte anonymous mapping as a placeholder.
            // We never read from it (len=0 guards all access).
            let anon = MmapOptions::new()
                .len(1)
                .map_anon()
                .map_err(|e| EngineError::Io(format!("anon mmap: {e}")))?
                .make_read_only()
                .map_err(|e| EngineError::Io(format!("anon mmap readonly: {e}")))?;
            return Ok(Self {
                _mmap: anon,
                ptr: std::ptr::NonNull::dangling().as_ptr(),
                len: 0,
                _marker: PhantomData,
            });
        }

        if !file_len.is_multiple_of(elem_size) {
            return Err(EngineError::Storage(format!(
                "{}: file size {} is not a multiple of element size {}",
                path.display(),
                file_len,
                elem_size
            )));
        }

        // SAFETY: the file is opened read-only; the mapping is never mutated.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| EngineError::Io(format!("{}: mmap failed: {}", path.display(), e)))?;

        let len = file_len / elem_size;
        let ptr = mmap.as_ptr().cast::<T>();

        // Verify alignment
        if !(ptr as usize).is_multiple_of(align_of::<T>()) {
            return Err(EngineError::Storage(format!(
                "{}: mmap address {:p} not aligned to {}",
                path.display(),
                ptr,
                align_of::<T>()
            )));
        }

        Ok(Self {
            _mmap: mmap,
            ptr,
            len,
            _marker: PhantomData,
        })
    }

    /// Number of elements.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get element by index. Returns `None` if out of bounds.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len {
            // SAFETY: index bounds-checked above; the mapping outlives self.
            Some(unsafe { &*self.ptr.add(index) })
        } else {
            None
        }
    }

    /// View the entire array as a slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        if self.len == 0 {
            &[]
        } else {
            // SAFETY: ptr/len describe the validated mapping of Pod elements.
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

/// A read-only memory-mapped byte slice (string table, property blobs).
pub struct MappedBytes {
    mmap: Mmap,
}

impl MappedBytes {
    /// # Errors
    /// Fails when the file cannot be opened or mapped.
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| EngineError::Io(format!("{}: {}", path.display(), e)))?;
        // SAFETY: read-only mapping, never mutated.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| EngineError::Io(format!("{}: mmap failed: {}", path.display(), e)))?;
        Ok(Self { mmap })
    }

    /// Get a byte slice at the given offset and length.
    #[inline]
    #[must_use]
    pub fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end <= self.mmap.len() {
            Some(&self.mmap[offset..end])
        } else {
            None
        }
    }

    /// Get a UTF-8 string at the given offset and length.
    #[inline]
    #[must_use]
    pub fn str_at(&self, offset: usize, len: usize) -> Option<&str> {
        let bytes = self.slice(offset, len)?;
        std::str::from_utf8(bytes).ok()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mmap.is_empty()
    }
}
