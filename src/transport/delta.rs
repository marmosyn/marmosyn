// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Delta synchronization using rolling checksums (rsync-like).
//!
//! This module implements the rolling checksum algorithm for efficient
//! delta transfers. Files are split into blocks, checksums are computed
//! for each block, and only changed blocks are transferred over the network.
//!
//! This is used by the transport layer to minimize bandwidth when syncing
//! files that have been partially modified.
//!
//! # Algorithm overview
//!
//! 1. The **receiver** splits the existing (old) file into fixed-size blocks
//!    and computes a weak rolling checksum (Adler32-like) and a strong
//!    BLAKE3 hash for each block.
//! 2. The **sender** receives this block signature list and scans the new
//!    file byte-by-byte using the rolling checksum. When a match is found
//!    (weak + strong), it emits a `BlockRef` instruction; otherwise it
//!    accumulates literal data bytes.
//! 3. The **receiver** reconstructs the new file by applying the delta
//!    instructions: copying matched blocks from the old file and inserting
//!    literal data where needed.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

/// Default block size for delta computation (4 KiB).
///
/// Smaller blocks produce finer-grained deltas but generate more metadata.
/// Larger blocks reduce metadata overhead but may miss small changes.
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Minimum block size to prevent degenerate behaviour.
pub const MIN_BLOCK_SIZE: usize = 512;

/// Maximum block size to keep memory usage reasonable.
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024; // 1 MiB

/// Modulus for the rolling checksum (prime, fits in u32).
const ROLLING_MOD: u32 = 65521;

/// Base for the rolling checksum (character offset to avoid zero-sums).
const ROLLING_OFFSET: u32 = 31;

// ─── Rolling checksum ──────────────────────────────────────────────────────

/// Adler32-inspired rolling checksum that can be updated incrementally
/// as a window slides over the data.
///
/// The checksum is composed of two 16-bit halves:
/// - `a`: sum of all bytes in the window (plus offset)
/// - `b`: sum of weighted byte values
///
/// Both halves are computed modulo [`ROLLING_MOD`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollingChecksum {
    /// Lower half: sum of bytes.
    a: u32,
    /// Upper half: weighted sum.
    b: u32,
    /// Current window size.
    window_size: usize,
}

impl RollingChecksum {
    /// Creates a new empty rolling checksum.
    pub fn new() -> Self {
        Self {
            a: 0,
            b: 0,
            window_size: 0,
        }
    }

    /// Computes the rolling checksum over an entire data block.
    pub fn from_block(data: &[u8]) -> Self {
        let mut cs = Self::new();
        for &byte in data {
            cs.push(byte);
        }
        cs
    }

    /// Returns the combined 32-bit checksum value.
    pub fn value(&self) -> u32 {
        (self.b << 16) | self.a
    }

    /// Appends a byte to the end of the window (grow phase or initial fill).
    pub fn push(&mut self, byte: u8) {
        let val = byte as u32 + ROLLING_OFFSET;
        self.a = (self.a + val) % ROLLING_MOD;
        self.b = (self.b + self.a) % ROLLING_MOD;
        self.window_size += 1;
    }

    /// Rolls the window forward: removes `old_byte` from the front and
    /// adds `new_byte` to the back. The window size stays the same.
    ///
    /// This is the O(1) incremental update that makes the algorithm efficient.
    pub fn roll(&mut self, old_byte: u8, new_byte: u8) {
        let old_val = old_byte as u32 + ROLLING_OFFSET;
        let new_val = new_byte as u32 + ROLLING_OFFSET;

        // Update `a`: subtract old, add new
        self.a = (self.a + ROLLING_MOD + new_val - old_val) % ROLLING_MOD;

        // Update `b`: subtract n*old_val, add new `a`
        let n = self.window_size as u32;
        // b_new = (b_old - n * old_val + a_new) mod M
        // We add ROLLING_MOD * n to avoid underflow before the modulo.
        self.b = (self.b + ROLLING_MOD * n - n * old_val + self.a) % ROLLING_MOD;
    }

    /// Resets the checksum to its initial state.
    pub fn reset(&mut self) {
        self.a = 0;
        self.b = 0;
        self.window_size = 0;
    }
}

impl Default for RollingChecksum {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Block signature ───────────────────────────────────────────────────────

/// Signature for a single block of the old file on the receiver side.
///
/// Contains both a weak (rolling) checksum for fast scanning and a strong
/// BLAKE3 hash for collision-resistant verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockSignature {
    /// Zero-based index of this block in the file.
    pub index: u32,
    /// Weak rolling checksum of the block.
    pub weak: u32,
    /// Strong BLAKE3 hash of the block (hex-encoded).
    pub strong: String,
    /// Actual size of this block in bytes (may be smaller than block_size
    /// for the last block).
    pub size: usize,
}

/// A complete signature for an entire file: the block size and all block signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileSignature {
    /// Block size used for splitting.
    pub block_size: usize,
    /// Ordered list of block signatures.
    pub blocks: Vec<BlockSignature>,
    /// Total file size in bytes.
    pub file_size: u64,
}

impl FileSignature {
    /// Returns the number of blocks in the signature.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns `true` if the signature describes an empty file.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Computes the block signatures for a file.
///
/// Reads the file in `block_size` chunks, computing a rolling checksum and
/// BLAKE3 hash for each chunk.
///
/// # Arguments
///
/// * `path` — path to the file to compute signatures for.
/// * `block_size` — size of each block (use [`DEFAULT_BLOCK_SIZE`] if unsure).
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn compute_signatures(path: &Path, block_size: usize) -> Result<FileSignature> {
    let block_size = block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open file for signatures: '{}'", path.display()))?;

    let file_size = file.metadata()?.len();

    let mut blocks = Vec::new();
    let mut buf = vec![0u8; block_size];
    let mut index = 0u32;

    loop {
        let bytes_read = read_full(&mut file, &mut buf)?;
        if bytes_read == 0 {
            break;
        }

        let block_data = &buf[..bytes_read];

        let weak = RollingChecksum::from_block(block_data).value();
        let strong = blake3::hash(block_data).to_hex().to_string();

        blocks.push(BlockSignature {
            index,
            weak,
            strong,
            size: bytes_read,
        });

        index += 1;

        if bytes_read < block_size {
            break; // Last (partial) block
        }
    }

    debug!(
        path = %path.display(),
        block_size = block_size,
        blocks = blocks.len(),
        file_size = file_size,
        "computed file signatures"
    );

    Ok(FileSignature {
        block_size,
        blocks,
        file_size,
    })
}

/// Computes signatures from raw data (useful for testing).
pub fn compute_signatures_from_data(data: &[u8], block_size: usize) -> FileSignature {
    let block_size = block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
    let mut blocks = Vec::new();

    for (i, chunk) in data.chunks(block_size).enumerate() {
        let weak = RollingChecksum::from_block(chunk).value();
        let strong = blake3::hash(chunk).to_hex().to_string();
        blocks.push(BlockSignature {
            index: i as u32,
            weak,
            strong,
            size: chunk.len(),
        });
    }

    FileSignature {
        block_size,
        blocks,
        file_size: data.len() as u64,
    }
}

// ─── Delta instructions ────────────────────────────────────────────────────

/// A single instruction in a delta: either copy a block from the old file
/// or insert literal data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeltaOp {
    /// Copy block `index` from the old file. The block's position and size
    /// are determined by the signature's block_size and the block's `size` field.
    BlockRef {
        /// Index of the block in the old file's signature.
        index: u32,
    },
    /// Insert literal data that does not match any old block.
    Literal {
        /// The raw bytes to insert.
        data: Vec<u8>,
    },
}

/// A complete delta: the set of instructions needed to reconstruct the new
/// file from the old file plus literal data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delta {
    /// The block size that was used for signature computation.
    pub block_size: usize,
    /// Ordered list of delta operations.
    pub ops: Vec<DeltaOp>,
    /// Total size of the new file (for verification).
    pub new_file_size: u64,
}

impl Delta {
    /// Returns the total number of operations in the delta.
    pub fn op_count(&self) -> usize {
        self.ops.len()
    }

    /// Returns the number of literal bytes in the delta.
    ///
    /// A lower value means more blocks were matched and less data needs
    /// to be transferred.
    pub fn literal_bytes(&self) -> u64 {
        self.ops
            .iter()
            .map(|op| match op {
                DeltaOp::Literal { data } => data.len() as u64,
                DeltaOp::BlockRef { .. } => 0,
            })
            .sum()
    }

    /// Returns the number of block references (matched blocks) in the delta.
    pub fn block_ref_count(&self) -> usize {
        self.ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::BlockRef { .. }))
            .count()
    }

    /// Returns `true` if the delta is empty (new file is empty).
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Estimates the transfer size: literal bytes plus a small overhead
    /// per BlockRef instruction.
    pub fn estimated_transfer_size(&self) -> u64 {
        self.ops
            .iter()
            .map(|op| match op {
                DeltaOp::Literal { data } => data.len() as u64,
                DeltaOp::BlockRef { .. } => 8, // index (4 bytes) + framing
            })
            .sum()
    }
}

// ─── Delta computation ─────────────────────────────────────────────────────

/// Computes a delta between a new file and an old file's signature.
///
/// Scans the new file byte-by-byte using a rolling checksum. When the
/// rolling checksum matches a block in the signature (weak match), the
/// strong hash is verified. Matched blocks produce `BlockRef` instructions;
/// unmatched regions produce `Literal` instructions.
///
/// # Arguments
///
/// * `new_data` — the contents of the new (updated) file.
/// * `signature` — the block signatures of the old file on the receiver.
///
/// # Returns
///
/// A [`Delta`] containing the instructions to reconstruct `new_data` from
/// the old file.
pub fn compute_delta(new_data: &[u8], signature: &FileSignature) -> Delta {
    if signature.is_empty() || new_data.is_empty() {
        // No old blocks to match against — entire file is literal
        let ops = if new_data.is_empty() {
            Vec::new()
        } else {
            vec![DeltaOp::Literal {
                data: new_data.to_vec(),
            }]
        };
        return Delta {
            block_size: signature.block_size,
            ops,
            new_file_size: new_data.len() as u64,
        };
    }

    let block_size = signature.block_size;

    // Build a lookup table: weak checksum → list of (block_index, strong_hash)
    let mut weak_map: HashMap<u32, Vec<(u32, &str)>> = HashMap::new();
    for sig in &signature.blocks {
        weak_map
            .entry(sig.weak)
            .or_default()
            .push((sig.index, &sig.strong));
    }

    let mut ops: Vec<DeltaOp> = Vec::new();
    let mut literal_buf: Vec<u8> = Vec::new();
    let mut pos: usize = 0;

    // Fill the initial rolling checksum window
    let initial_end = block_size.min(new_data.len());
    let mut rolling = RollingChecksum::from_block(&new_data[..initial_end]);

    loop {
        let window_end = pos + block_size;
        let window_end = window_end.min(new_data.len());
        let window_len = window_end - pos;

        if window_len == 0 {
            break;
        }

        // Check for a weak match
        let weak_val = rolling.value();
        let mut matched = false;

        if let Some(candidates) = weak_map.get(&weak_val) {
            // Verify with strong hash
            let window = &new_data[pos..window_end];
            let strong = blake3::hash(window).to_hex().to_string();

            for &(block_idx, block_strong) in candidates {
                // Also check the block size matches
                let block_sig = &signature.blocks[block_idx as usize];
                if block_strong == strong && block_sig.size == window_len {
                    // Match found!
                    trace!(pos = pos, block_idx = block_idx, "delta: matched block");

                    // Flush any accumulated literal data
                    if !literal_buf.is_empty() {
                        ops.push(DeltaOp::Literal {
                            data: std::mem::take(&mut literal_buf),
                        });
                    }

                    ops.push(DeltaOp::BlockRef { index: block_idx });
                    pos += window_len;
                    matched = true;

                    // Re-initialize rolling checksum for the next window
                    let next_end = (pos + block_size).min(new_data.len());
                    if pos < new_data.len() {
                        rolling = RollingChecksum::from_block(&new_data[pos..next_end]);
                    }
                    break;
                }
            }
        }

        if !matched {
            // No match: consume one byte as literal and roll the window forward
            literal_buf.push(new_data[pos]);
            pos += 1;

            if pos < new_data.len() {
                let next_end = (pos + block_size).min(new_data.len());
                if next_end - pos == block_size && pos > 0 {
                    // Roll incrementally: remove old byte, add new byte
                    let old_byte = new_data[pos - 1];
                    if next_end <= new_data.len() {
                        let new_byte = new_data[next_end - 1];
                        rolling.roll(old_byte, new_byte);
                    } else {
                        // Near the end of file, recompute
                        rolling = RollingChecksum::from_block(&new_data[pos..next_end]);
                    }
                } else {
                    // Window size changed (near end of file), recompute
                    rolling = RollingChecksum::from_block(&new_data[pos..next_end]);
                }
            }
        }
    }

    // Flush remaining literal data
    if !literal_buf.is_empty() {
        ops.push(DeltaOp::Literal {
            data: std::mem::take(&mut literal_buf),
        });
    }

    debug!(
        ops = ops.len(),
        block_refs = ops
            .iter()
            .filter(|o| matches!(o, DeltaOp::BlockRef { .. }))
            .count(),
        literal_bytes = ops
            .iter()
            .map(|o| match o {
                DeltaOp::Literal { data } => data.len(),
                _ => 0,
            })
            .sum::<usize>(),
        new_size = new_data.len(),
        "delta computation complete"
    );

    Delta {
        block_size,
        ops,
        new_file_size: new_data.len() as u64,
    }
}

/// Computes a delta from a file on disk.
///
/// Convenience wrapper around [`compute_delta`] that reads the file first.
pub fn compute_delta_from_file(new_path: &Path, signature: &FileSignature) -> Result<Delta> {
    let new_data = std::fs::read(new_path)
        .with_context(|| format!("failed to read new file '{}'", new_path.display()))?;
    Ok(compute_delta(&new_data, signature))
}

// ─── Delta application ─────────────────────────────────────────────────────

/// Applies a delta to reconstruct a new file from an old file.
///
/// Reads blocks from the old file as referenced by `BlockRef` instructions
/// and inserts literal data, writing the result to the output writer.
///
/// # Arguments
///
/// * `old_path` — path to the old (existing) file on the receiver.
/// * `delta` — the delta instructions from the sender.
/// * `output` — writer where the reconstructed file is written.
///
/// # Errors
///
/// Returns an error if the old file cannot be read, if a block reference
/// is out of range, or if the output cannot be written.
pub fn apply_delta<W: Write>(old_path: &Path, delta: &Delta, mut output: W) -> Result<u64> {
    let old_data = if old_path.exists() {
        std::fs::read(old_path)
            .with_context(|| format!("failed to read old file '{}'", old_path.display()))?
    } else {
        Vec::new()
    };

    let mut bytes_written: u64 = 0;

    for op in &delta.ops {
        match op {
            DeltaOp::BlockRef { index } => {
                let idx = *index as usize;
                let block_offset = idx * delta.block_size;
                let block_end = (block_offset + delta.block_size).min(old_data.len());

                if block_offset >= old_data.len() {
                    anyhow::bail!(
                        "block reference {} out of range (old file size: {}, \
                         block offset: {})",
                        index,
                        old_data.len(),
                        block_offset
                    );
                }

                let block_data = &old_data[block_offset..block_end];
                output.write_all(block_data)?;
                bytes_written += block_data.len() as u64;
            }
            DeltaOp::Literal { data } => {
                output.write_all(data)?;
                bytes_written += data.len() as u64;
            }
        }
    }

    if bytes_written != delta.new_file_size {
        anyhow::bail!(
            "delta application produced {} bytes, expected {}",
            bytes_written,
            delta.new_file_size
        );
    }

    debug!(
        bytes = bytes_written,
        ops = delta.ops.len(),
        "delta applied successfully"
    );

    Ok(bytes_written)
}

/// Applies a delta and writes the result to a file path.
///
/// This is a convenience wrapper that creates the output file and calls
/// [`apply_delta`].
pub fn apply_delta_to_file(old_path: &Path, delta: &Delta, new_path: &Path) -> Result<u64> {
    if let Some(parent) = new_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create parent directory for '{}'",
                new_path.display()
            )
        })?;
    }

    let output = std::fs::File::create(new_path)
        .with_context(|| format!("failed to create output file '{}'", new_path.display()))?;

    let writer = io::BufWriter::new(output);
    apply_delta(old_path, delta, writer)
}

// ─── Helper ────────────────────────────────────────────────────────────────

/// Reads as many bytes as possible into `buf`, returning the actual count.
/// Unlike `read_exact`, this does not error on a short read at EOF.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── RollingChecksum tests ───────────────────────────────────────────

    #[test]
    fn test_rolling_checksum_empty() {
        let cs = RollingChecksum::new();
        assert_eq!(cs.value(), 0);
        assert_eq!(cs.window_size, 0);
    }

    #[test]
    fn test_rolling_checksum_from_block() {
        let data = b"hello world";
        let cs = RollingChecksum::from_block(data);
        assert_ne!(cs.value(), 0);
        assert_eq!(cs.window_size, data.len());
    }

    #[test]
    fn test_rolling_checksum_deterministic() {
        let data = b"test data here";
        let cs1 = RollingChecksum::from_block(data);
        let cs2 = RollingChecksum::from_block(data);
        assert_eq!(cs1.value(), cs2.value());
    }

    #[test]
    fn test_rolling_checksum_different_data() {
        let cs1 = RollingChecksum::from_block(b"aaa");
        let cs2 = RollingChecksum::from_block(b"bbb");
        assert_ne!(cs1.value(), cs2.value());
    }

    #[test]
    fn test_rolling_checksum_push() {
        let mut cs = RollingChecksum::new();
        for &b in b"abc" {
            cs.push(b);
        }
        let direct = RollingChecksum::from_block(b"abc");
        assert_eq!(cs.value(), direct.value());
    }

    #[test]
    fn test_rolling_checksum_roll() {
        // Build checksum for "abcd" then roll to "bcde"
        let block1 = b"abcd";
        let block2 = b"bcde";

        let mut rolling = RollingChecksum::from_block(block1);
        rolling.roll(b'a', b'e');

        let direct = RollingChecksum::from_block(block2);
        assert_eq!(rolling.value(), direct.value());
    }

    #[test]
    fn test_rolling_checksum_roll_multiple_steps() {
        // Roll through "abcdef" one byte at a time with window size 3
        let data = b"abcdef";
        let window = 3;

        let mut rolling = RollingChecksum::from_block(&data[..window]);

        for i in 1..=(data.len() - window) {
            rolling.roll(data[i - 1], data[i + window - 1]);
            let expected = RollingChecksum::from_block(&data[i..i + window]);
            assert_eq!(
                rolling.value(),
                expected.value(),
                "mismatch at position {i}"
            );
        }
    }

    #[test]
    fn test_rolling_checksum_reset() {
        let mut cs = RollingChecksum::from_block(b"data");
        assert_ne!(cs.value(), 0);
        cs.reset();
        assert_eq!(cs.value(), 0);
        assert_eq!(cs.window_size, 0);
    }

    #[test]
    fn test_rolling_checksum_default() {
        let cs = RollingChecksum::default();
        assert_eq!(cs.value(), 0);
    }

    // ── Signature tests ────────────────────────────────────────────────

    #[test]
    fn test_compute_signatures_from_data_empty() {
        let sig = compute_signatures_from_data(b"", MIN_BLOCK_SIZE);
        assert!(sig.is_empty());
        assert_eq!(sig.block_count(), 0);
        assert_eq!(sig.file_size, 0);
    }

    #[test]
    fn test_compute_signatures_from_data_single_block() {
        let data = vec![0xABu8; MIN_BLOCK_SIZE];
        let sig = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);
        assert_eq!(sig.block_count(), 1);
        assert_eq!(sig.blocks[0].index, 0);
        assert_eq!(sig.blocks[0].size, MIN_BLOCK_SIZE);
        assert_eq!(sig.file_size, MIN_BLOCK_SIZE as u64);
    }

    #[test]
    fn test_compute_signatures_from_data_multiple_blocks() {
        let data = vec![0x42u8; MIN_BLOCK_SIZE * 3 + 100];
        let sig = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);
        assert_eq!(sig.block_count(), 4); // 3 full + 1 partial
        assert_eq!(sig.blocks[3].size, 100); // Last block is partial
        assert_eq!(sig.blocks[0].index, 0);
        assert_eq!(sig.blocks[1].index, 1);
        assert_eq!(sig.blocks[2].index, 2);
        assert_eq!(sig.blocks[3].index, 3);
    }

    #[test]
    fn test_compute_signatures_from_data_exact_multiple() {
        let data = vec![0x42u8; MIN_BLOCK_SIZE * 2];
        let sig = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);
        assert_eq!(sig.block_count(), 2);
        assert_eq!(sig.blocks[0].size, MIN_BLOCK_SIZE);
        assert_eq!(sig.blocks[1].size, MIN_BLOCK_SIZE);
    }

    #[test]
    fn test_compute_signatures_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        let data = vec![0xCDu8; MIN_BLOCK_SIZE * 2 + 50];
        std::fs::write(&path, &data).unwrap();

        let sig = compute_signatures(&path, MIN_BLOCK_SIZE).unwrap();
        let sig_data = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);

        assert_eq!(sig.block_count(), sig_data.block_count());
        for (a, b) in sig.blocks.iter().zip(sig_data.blocks.iter()) {
            assert_eq!(a.weak, b.weak);
            assert_eq!(a.strong, b.strong);
            assert_eq!(a.size, b.size);
        }
    }

    #[test]
    fn test_compute_signatures_block_size_clamping() {
        let data = vec![0xABu8; 1000];
        // Block size below minimum should be clamped to MIN_BLOCK_SIZE
        let sig = compute_signatures_from_data(&data, 1);
        assert_eq!(sig.block_size, MIN_BLOCK_SIZE);
    }

    #[test]
    fn test_compute_signatures_nonexistent_file() {
        let result = compute_signatures(Path::new("/nonexistent/file.bin"), MIN_BLOCK_SIZE);
        assert!(result.is_err());
    }

    // ── Delta computation tests ────────────────────────────────────────

    #[test]
    fn test_delta_identical_files() {
        let data = vec![0xABu8; MIN_BLOCK_SIZE * 3];
        let sig = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&data, &sig);

        // All blocks should be BlockRef instructions
        assert_eq!(delta.block_ref_count(), 3);
        assert_eq!(delta.literal_bytes(), 0);
        assert_eq!(delta.new_file_size, data.len() as u64);
    }

    #[test]
    fn test_delta_completely_different() {
        let old_data = vec![0xAAu8; MIN_BLOCK_SIZE * 2];
        let new_data = vec![0xBBu8; MIN_BLOCK_SIZE * 2];
        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        // No blocks should match
        assert_eq!(delta.block_ref_count(), 0);
        assert_eq!(delta.literal_bytes(), new_data.len() as u64);
    }

    #[test]
    fn test_delta_empty_old_file() {
        let sig = compute_signatures_from_data(b"", MIN_BLOCK_SIZE);
        let new_data = b"hello world new file";
        let delta = compute_delta(new_data, &sig);

        assert_eq!(delta.block_ref_count(), 0);
        assert_eq!(delta.literal_bytes(), new_data.len() as u64);
    }

    #[test]
    fn test_delta_empty_new_file() {
        let old_data = vec![0xABu8; MIN_BLOCK_SIZE];
        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(b"", &sig);

        assert!(delta.is_empty());
        assert_eq!(delta.new_file_size, 0);
    }

    #[test]
    fn test_delta_appended_data() {
        // Old file: 2 blocks. New file: same 2 blocks + extra data.
        let old_data = vec![0xAAu8; MIN_BLOCK_SIZE * 2];
        let mut new_data = old_data.clone();
        new_data.extend_from_slice(b"appended tail data here");

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        // The first 2 blocks should be matched
        assert_eq!(delta.block_ref_count(), 2);
        // The appended data should be literal
        assert!(delta.literal_bytes() > 0);
        assert_eq!(delta.new_file_size, new_data.len() as u64);
    }

    #[test]
    fn test_delta_prepended_data() {
        // Old file: 2 blocks. New file: prepended data + same 2 blocks.
        let old_data = vec![0xBBu8; MIN_BLOCK_SIZE * 2];
        let mut new_data = b"prepended header data!!".to_vec();
        new_data.extend_from_slice(&old_data);

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        // The 2 original blocks should still be found
        assert!(delta.block_ref_count() >= 1);
        assert!(delta.literal_bytes() > 0);
        assert_eq!(delta.new_file_size, new_data.len() as u64);
    }

    #[test]
    fn test_delta_middle_insertion() {
        // Old: block_A + block_B. New: block_A + inserted + block_B
        let block_a = vec![0x11u8; MIN_BLOCK_SIZE];
        let block_b = vec![0x22u8; MIN_BLOCK_SIZE];

        let mut old_data = block_a.clone();
        old_data.extend_from_slice(&block_b);

        let mut new_data = block_a.clone();
        new_data.extend_from_slice(b"inserted in the middle");
        new_data.extend_from_slice(&block_b);

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        // Both original blocks should be found, plus literal for the insertion
        assert!(delta.block_ref_count() >= 1);
        assert!(delta.literal_bytes() > 0);
        assert_eq!(delta.new_file_size, new_data.len() as u64);
    }

    #[test]
    fn test_delta_op_count() {
        let delta = Delta {
            block_size: MIN_BLOCK_SIZE,
            ops: vec![
                DeltaOp::BlockRef { index: 0 },
                DeltaOp::Literal {
                    data: vec![1, 2, 3],
                },
                DeltaOp::BlockRef { index: 1 },
            ],
            new_file_size: 100,
        };
        assert_eq!(delta.op_count(), 3);
        assert_eq!(delta.block_ref_count(), 2);
        assert_eq!(delta.literal_bytes(), 3);
    }

    #[test]
    fn test_delta_estimated_transfer_size() {
        let delta = Delta {
            block_size: MIN_BLOCK_SIZE,
            ops: vec![
                DeltaOp::BlockRef { index: 0 },
                DeltaOp::Literal { data: vec![0; 100] },
            ],
            new_file_size: 612,
        };
        // 8 bytes for the BlockRef + 100 bytes for the literal
        assert_eq!(delta.estimated_transfer_size(), 108);
    }

    // ── Delta application tests ────────────────────────────────────────

    #[test]
    fn test_apply_delta_identical_files() {
        let data = vec![0xABu8; MIN_BLOCK_SIZE * 3];
        let sig = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&data, &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &data).unwrap();

        let mut output = Vec::new();
        let bytes = apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(bytes, data.len() as u64);
        assert_eq!(output, data);
    }

    #[test]
    fn test_apply_delta_completely_different() {
        let old_data = vec![0xAAu8; MIN_BLOCK_SIZE * 2];
        let new_data = vec![0xBBu8; MIN_BLOCK_SIZE * 2];
        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        let bytes = apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(bytes, new_data.len() as u64);
        assert_eq!(output, new_data);
    }

    #[test]
    fn test_apply_delta_appended_data() {
        let old_data = vec![0xCCu8; MIN_BLOCK_SIZE * 2];
        let mut new_data = old_data.clone();
        new_data.extend_from_slice(b"appended tail");

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        let bytes = apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(bytes, new_data.len() as u64);
        assert_eq!(output, new_data);
    }

    #[test]
    fn test_apply_delta_empty_new_file() {
        let old_data = vec![0xAAu8; MIN_BLOCK_SIZE];
        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(b"", &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        let bytes = apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(bytes, 0);
        assert!(output.is_empty());
    }

    #[test]
    fn test_apply_delta_to_file() {
        let old_data = vec![0xDDu8; MIN_BLOCK_SIZE * 2];
        let mut new_data = old_data.clone();
        new_data.extend_from_slice(b"extra");

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        let new_path = dir.path().join("new.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let bytes = apply_delta_to_file(&old_path, &delta, &new_path).unwrap();

        assert_eq!(bytes, new_data.len() as u64);
        let written = std::fs::read(&new_path).unwrap();
        assert_eq!(written, new_data);
    }

    #[test]
    fn test_apply_delta_block_ref_out_of_range() {
        let delta = Delta {
            block_size: MIN_BLOCK_SIZE,
            ops: vec![DeltaOp::BlockRef { index: 999 }],
            new_file_size: 100,
        };

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("small.bin");
        std::fs::write(&old_path, b"small").unwrap();

        let mut output = Vec::new();
        let result = apply_delta(&old_path, &delta, &mut output);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("out of range"));
    }

    #[test]
    fn test_apply_delta_nonexistent_old_with_literals_only() {
        // If old file doesn't exist and all ops are literals, it should still work
        let delta = Delta {
            block_size: MIN_BLOCK_SIZE,
            ops: vec![DeltaOp::Literal {
                data: b"brand new content".to_vec(),
            }],
            new_file_size: 17,
        };

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("nonexistent.bin");

        let mut output = Vec::new();
        let bytes = apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(bytes, 17);
        assert_eq!(output, b"brand new content");
    }

    // ── End-to-end roundtrip tests ─────────────────────────────────────

    #[test]
    fn test_roundtrip_simple_modification() {
        let _old = b"AAAA BBBB CCCC DDDD"; // Simplified, using real block sizes below
        let _new = b"AAAA XXXX CCCC DDDD";

        // Using minimum block size for the test
        let old_data = {
            let mut d = vec![0xAAu8; MIN_BLOCK_SIZE];
            d.extend(vec![0xBBu8; MIN_BLOCK_SIZE]);
            d.extend(vec![0xCCu8; MIN_BLOCK_SIZE]);
            d
        };

        let new_data = {
            let mut d = vec![0xAAu8; MIN_BLOCK_SIZE];
            d.extend(vec![0xFFu8; MIN_BLOCK_SIZE]); // Changed block
            d.extend(vec![0xCCu8; MIN_BLOCK_SIZE]);
            d
        };

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        // Blocks 0 and 2 should be refs, block 1 should be literal
        assert!(delta.block_ref_count() >= 2);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(output, new_data);
    }

    #[test]
    fn test_roundtrip_real_text_file() {
        // Simulate a config file where a few lines change
        let mut old_lines = Vec::new();
        for i in 0..100 {
            old_lines.push(format!("line {:04}: original content here padding\n", i));
        }
        let old_data: Vec<u8> = old_lines.concat().into_bytes();

        let mut new_lines = old_lines.clone();
        new_lines[50] = "line 0050: MODIFIED content here padding!!\n".to_string();
        new_lines[51] = "line 0051: ALSO MODIFIED content padding!!\n".to_string();
        let new_data: Vec<u8> = new_lines.concat().into_bytes();

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        // Some blocks should be reused
        assert!(delta.block_ref_count() > 0);
        // But not all data is literal
        assert!(delta.literal_bytes() < new_data.len() as u64);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.txt");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(output, new_data);
    }

    #[test]
    fn test_roundtrip_large_file_small_change() {
        // Large file with a tiny change near the end
        let size = MIN_BLOCK_SIZE * 20;
        let mut old_data = vec![0u8; size];
        // Fill with pseudo-random but deterministic data
        for (i, byte) in old_data.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }

        let mut new_data = old_data.clone();
        // Change just a few bytes near the end
        let change_pos = size - MIN_BLOCK_SIZE / 2;
        for byte in new_data.iter_mut().skip(change_pos).take(10) {
            *byte = 0xFF;
        }

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        // Most blocks should be reused
        assert!(delta.block_ref_count() >= 18);

        // Transfer size should be much smaller than full file
        assert!(delta.estimated_transfer_size() < new_data.len() as u64 / 2);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        apply_delta(&old_path, &delta, &mut output).unwrap();

        assert_eq!(output, new_data);
    }

    #[test]
    fn test_delta_from_file() {
        let dir = tempfile::tempdir().unwrap();

        let old_data = vec![0xABu8; MIN_BLOCK_SIZE * 3];
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut new_data = old_data.clone();
        new_data.extend_from_slice(b"extra data at end");
        let new_path = dir.path().join("new.bin");
        std::fs::write(&new_path, &new_data).unwrap();

        let sig = compute_signatures(&old_path, MIN_BLOCK_SIZE).unwrap();
        let delta = compute_delta_from_file(&new_path, &sig).unwrap();

        assert!(delta.block_ref_count() >= 2);
        assert_eq!(delta.new_file_size, new_data.len() as u64);

        // Apply and verify
        let mut output = Vec::new();
        apply_delta(&old_path, &delta, &mut output).unwrap();
        assert_eq!(output, new_data);
    }

    // ── FileSignature serde tests ──────────────────────────────────────

    #[test]
    fn test_file_signature_serde_roundtrip() {
        let data = vec![0x42u8; MIN_BLOCK_SIZE * 2 + 100];
        let sig = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);

        let json = serde_json::to_string(&sig).unwrap();
        let deserialized: FileSignature = serde_json::from_str(&json).unwrap();

        assert_eq!(sig, deserialized);
    }

    #[test]
    fn test_delta_serde_roundtrip() {
        let old_data = vec![0xAAu8; MIN_BLOCK_SIZE * 2];
        let mut new_data = old_data.clone();
        new_data.extend_from_slice(b"extra");

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        let json = serde_json::to_string(&delta).unwrap();
        let deserialized: Delta = serde_json::from_str(&json).unwrap();

        assert_eq!(delta, deserialized);
    }

    // ── Edge case tests ────────────────────────────────────────────────

    #[test]
    fn test_delta_single_byte_file() {
        let old_data = vec![0xAA; 1];
        let new_data = vec![0xBB; 1];

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        apply_delta(&old_path, &delta, &mut output).unwrap();
        assert_eq!(output, new_data);
    }

    #[test]
    fn test_delta_block_size_equals_file_size() {
        let data = vec![0xCD; MIN_BLOCK_SIZE];
        let sig = compute_signatures_from_data(&data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&data, &sig);

        assert_eq!(delta.block_ref_count(), 1);
        assert_eq!(delta.literal_bytes(), 0);
    }

    #[test]
    fn test_delta_new_file_larger_than_old() {
        let old_data = vec![0xAA; MIN_BLOCK_SIZE];
        let new_data = vec![0xAA; MIN_BLOCK_SIZE * 5];

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        apply_delta(&old_path, &delta, &mut output).unwrap();
        assert_eq!(output, new_data);
    }

    #[test]
    fn test_delta_new_file_smaller_than_old() {
        let old_data = vec![0xBB; MIN_BLOCK_SIZE * 5];
        let new_data = vec![0xBB; MIN_BLOCK_SIZE];

        let sig = compute_signatures_from_data(&old_data, MIN_BLOCK_SIZE);
        let delta = compute_delta(&new_data, &sig);

        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.bin");
        std::fs::write(&old_path, &old_data).unwrap();

        let mut output = Vec::new();
        apply_delta(&old_path, &delta, &mut output).unwrap();
        assert_eq!(output, new_data);
    }

    #[test]
    fn test_rolling_checksum_single_byte_window() {
        let cs = RollingChecksum::from_block(&[42]);
        assert_ne!(cs.value(), 0);
        assert_eq!(cs.window_size, 1);
    }

    #[test]
    fn test_read_full_short_read() {
        // Simulate a read that returns fewer bytes than requested
        let data = b"hello";
        let mut cursor = Cursor::new(data.as_slice());
        let mut buf = [0u8; 10]; // Larger than available
        let n = read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn test_read_full_exact() {
        let data = b"exact";
        let mut cursor = Cursor::new(data.as_slice());
        let mut buf = [0u8; 5];
        let n = read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"exact");
    }
}
