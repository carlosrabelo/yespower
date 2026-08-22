//! Reference yespower implementation (port of Openwall `yespower-ref.c`).
//!
//! # Big picture
//!
//! yespower stretches an input (`src`, often an 80-byte block header) into a
//! large RAM-hard state, then folds it back into a 32-byte digest. Rough flow:
//!
//! ```text
//! src ──SHA-256──► password
//!        │
//!        ▼
//!   PBKDF2-SHA256 (1 round) ──► working block B   (size 128·r bytes)
//!        │
//!        ▼
//!      SMix  (S-box init → fill V[0..N) → random RO/RW passes)
//!        │
//!        ▼
//!   finalize (v0.5: PBKDF2 + optional HMAC; v1.0: HMAC over B tail)
//!        │
//!        ▼
//!     32-byte hash
//! ```
//!
//! The expensive part is **SMix**: it allocates about `128 · N · r` bytes in
//! array `V` and walks it with data-dependent indices, which is why GPUs
//! struggle (irregular memory access).
//!
//! Inside SMix, mixing is done with **pwxform** (parallel wide transform using
//! S-boxes) plus a final **Salsa20/8 or Salsa20/2** round on each sub-block.
//!
//! Unit tests for private helpers are in [`tests`] (`cargo test --lib`).

use crate::sha256::{
    bytes_from_words, hmac_sha256, le32dec_word, le32enc_word, pbkdf2_sha256, sha256,
    words_from_bytes,
};
use crate::{Error, Params, Version};

// ---------------------------------------------------------------------------
// Tunables copied from the C reference (pwxform / S-box geometry)
// ---------------------------------------------------------------------------

/// Number of 64-bit lanes processed as one "simple" unit inside pwxform.
const PWX_SIMPLE: usize = 2;
/// How many gather slots (independent S-box lookups) run in parallel.
const PWX_GATHER: usize = 4;
/// pwxform round counts differ by version.
const PWX_ROUNDS_0_5: u32 = 6;
const PWX_ROUNDS_1_0: u32 = 3;
/// log2 of the number of S-box entries per table (v0.5 uses smaller tables).
const SWIDTH_0_5: u32 = 8;
const SWIDTH_1_0: u32 = 11;

/// Bytes touched by one pwxform invocation (= gather · simple · 8).
const PWX_BYTES: usize = PWX_GATHER * PWX_SIMPLE * 8;
const PWX_WORDS: usize = PWX_BYTES / 4;
/// Minimum legal `r`: working block must be at least one pwxform chunk.
const RMIN: u32 = PWX_BYTES.div_ceil(128) as u32;

/// Bytes in one S-box table for a given `swidth`.
#[inline]
fn swidth_to_sbytes1(swidth: u32) -> usize {
    (1usize << swidth) * PWX_SIMPLE * 8
}

/// Mask used to turn a 32-bit word into an S-box index.
#[inline]
fn swidth_to_smask(swidth: u32) -> u32 {
    ((1u32 << swidth) - 1) * (PWX_SIMPLE as u32) * 8
}

/// Mutable state threaded through pwxform / BlockMix.
///
/// `s0` / `s1` / `s2` are base indices (in *pairs*) into the flat S-box
/// buffer `s`. In v1.0 those three windows rotate after each pwxform call.
struct PwxformCtx {
    version: Version,
    /// Salsa20 rounds used after pwxform (8 for v0.5, 2 for v1.0).
    salsa20_rounds: u32,
    pwx_rounds: u32,
    swidth: u32,
    sbytes: usize,
    smask: u32,
    /// Pair indices into `s` (each pair is two `u32`s = one 64-bit lane).
    s0: usize,
    s1: usize,
    s2: usize,
    /// Write cursor for S-box updates (v1.0 only).
    w: usize,
}

// ---------------------------------------------------------------------------
// Tiny block helpers (same roles as in scrypt / yescrypt C)
// ---------------------------------------------------------------------------

fn blkcpy(dst: &mut [u32], src: &[u32]) {
    dst.copy_from_slice(src);
}

fn blkxor(dst: &mut [u32], src: &[u32]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Salsa20 core on a 16-word (64-byte) block.
///
/// The `i * 5 % 16` permutation is the classic "SIMD shuffle": the C SIMD
/// code stores words in a different order than the pure scalar specification,
/// so the reference scalar code undoes that layout before the quarter-rounds
/// and restores it afterwards.
fn salsa20(b: &mut [u32], rounds: u32) {
    debug_assert!(b.len() >= 16);
    let mut x = [0u32; 16];

    // SIMD unshuffle → scalar column/row order
    for i in 0..16 {
        x[i * 5 % 16] = b[i];
    }

    // Each loop iteration does one column round + one row round (= 2 of the
    // "rounds" count). So `rounds = 8` means 4 iterations here.
    let mut i = 0u32;
    while i < rounds {
        #[inline(always)]
        fn r(a: u32, b: u32) -> u32 {
            a.rotate_left(b)
        }

        // column rounds
        x[4] ^= r(x[0].wrapping_add(x[12]), 7);
        x[8] ^= r(x[4].wrapping_add(x[0]), 9);
        x[12] ^= r(x[8].wrapping_add(x[4]), 13);
        x[0] ^= r(x[12].wrapping_add(x[8]), 18);

        x[9] ^= r(x[5].wrapping_add(x[1]), 7);
        x[13] ^= r(x[9].wrapping_add(x[5]), 9);
        x[1] ^= r(x[13].wrapping_add(x[9]), 13);
        x[5] ^= r(x[1].wrapping_add(x[13]), 18);

        x[14] ^= r(x[10].wrapping_add(x[6]), 7);
        x[2] ^= r(x[14].wrapping_add(x[10]), 9);
        x[6] ^= r(x[2].wrapping_add(x[14]), 13);
        x[10] ^= r(x[6].wrapping_add(x[2]), 18);

        x[3] ^= r(x[15].wrapping_add(x[11]), 7);
        x[7] ^= r(x[3].wrapping_add(x[15]), 9);
        x[11] ^= r(x[7].wrapping_add(x[3]), 13);
        x[15] ^= r(x[11].wrapping_add(x[7]), 18);

        // row rounds
        x[1] ^= r(x[0].wrapping_add(x[3]), 7);
        x[2] ^= r(x[1].wrapping_add(x[0]), 9);
        x[3] ^= r(x[2].wrapping_add(x[1]), 13);
        x[0] ^= r(x[3].wrapping_add(x[2]), 18);

        x[6] ^= r(x[5].wrapping_add(x[4]), 7);
        x[7] ^= r(x[6].wrapping_add(x[5]), 9);
        x[4] ^= r(x[7].wrapping_add(x[6]), 13);
        x[5] ^= r(x[4].wrapping_add(x[7]), 18);

        x[11] ^= r(x[10].wrapping_add(x[9]), 7);
        x[8] ^= r(x[11].wrapping_add(x[10]), 9);
        x[9] ^= r(x[8].wrapping_add(x[11]), 13);
        x[10] ^= r(x[9].wrapping_add(x[8]), 18);

        x[12] ^= r(x[15].wrapping_add(x[14]), 7);
        x[13] ^= r(x[12].wrapping_add(x[15]), 9);
        x[14] ^= r(x[13].wrapping_add(x[12]), 13);
        x[15] ^= r(x[14].wrapping_add(x[13]), 18);

        i += 2;
    }

    // SIMD shuffle + add original block (Salsa20 feed-forward)
    for i in 0..16 {
        b[i] = b[i].wrapping_add(x[i * 5 % 16]);
    }
}

/// BlockMix with plain Salsa20 — used only while initializing the S-box
/// (`smix1_sbox`), where the "block" is a single 128-byte salsa block pair.
fn blockmix_salsa(b: &mut [u32], rounds: u32) {
    let mut x = [0u32; 16];
    blkcpy(&mut x, &b[16..32]);

    for i in 0..2 {
        blkxor(&mut x, &b[i * 16..i * 16 + 16]);
        salsa20(&mut x, rounds);
        blkcpy(&mut b[i * 16..i * 16 + 16], &x);
    }
}

// S-box entries are stored as (lo, hi) u32 pairs (= one little-endian u64).

fn pair_lo(s: &[u32], base_pairs: usize, idx: usize) -> u32 {
    s[(base_pairs + idx) * 2]
}

fn pair_hi(s: &[u32], base_pairs: usize, idx: usize) -> u32 {
    s[(base_pairs + idx) * 2 + 1]
}

fn set_pair(s: &mut [u32], base_pairs: usize, idx: usize, lo: u32, hi: u32) {
    s[(base_pairs + idx) * 2] = lo;
    s[(base_pairs + idx) * 2 + 1] = hi;
}

/// Parallel wide transform: multiply-xor against two S-box tables.
///
/// For each gather slot `j`, the low/high words of the current state select
/// indices into S0 and S1. Then for each simple lane we compute:
///
/// ```text
/// x = (xh * xl) + S0[p0]  XOR  S1[p1]
/// ```
///
/// In v1.0, parts of the new state are written back into the S-boxes (random
/// writes) and the (S0, S1, S2) windows rotate — another GPU-hostile twist.
fn pwxform(b: &mut [u32], s: &mut [u32], ctx: &mut PwxformCtx) {
    // Memory layout of `b`: X[j][k][0/1] → b[j*PWX_SIMPLE*2 + k*2 + 0/1]
    let mut w = ctx.w;
    let smask = ctx.smask;
    let s0 = ctx.s0;
    let s1 = ctx.s1;
    let s2 = ctx.s2;

    for i in 0..ctx.pwx_rounds {
        for j in 0..PWX_GATHER {
            let xl = b[j * PWX_SIMPLE * 2];
            let xh = b[j * PWX_SIMPLE * 2 + 1];
            // Mask + /8: convert word bits into a pair-index into the S-box.
            let p0 = (xl & smask) as usize / 8;
            let p1 = (xh & smask) as usize / 8;

            for k in 0..PWX_SIMPLE {
                let s0v = ((pair_hi(s, s0, p0 + k) as u64) << 32) + pair_lo(s, s0, p0 + k) as u64;
                let s1v = ((pair_hi(s, s1, p1 + k) as u64) << 32) + pair_lo(s, s1, p1 + k) as u64;

                let xl = b[j * PWX_SIMPLE * 2 + k * 2];
                let xh = b[j * PWX_SIMPLE * 2 + k * 2 + 1];

                let mut x = (xh as u64).wrapping_mul(xl as u64);
                x = x.wrapping_add(s0v);
                x ^= s1v;

                b[j * PWX_SIMPLE * 2 + k * 2] = x as u32;
                b[j * PWX_SIMPLE * 2 + k * 2 + 1] = (x >> 32) as u32;
            }

            // v1.0: write updated lanes back into S0/S1 (S-box "random writes").
            if ctx.version != Version::V0_5 && (i == 0 || j < PWX_GATHER / 2) {
                if j & 1 != 0 {
                    for k in 0..PWX_SIMPLE {
                        let lo = b[j * PWX_SIMPLE * 2 + k * 2];
                        let hi = b[j * PWX_SIMPLE * 2 + k * 2 + 1];
                        set_pair(s, s1, w, lo, hi);
                        w += 1;
                    }
                } else {
                    for k in 0..PWX_SIMPLE {
                        let lo = b[j * PWX_SIMPLE * 2 + k * 2];
                        let hi = b[j * PWX_SIMPLE * 2 + k * 2 + 1];
                        set_pair(s, s0, w + k, lo, hi);
                    }
                }
            }
        }
    }

    if ctx.version != Version::V0_5 {
        // Rotate the three S-box windows: (S0, S1, S2) ← (S2, S0, S1)
        ctx.s0 = s2;
        ctx.s1 = s0;
        ctx.s2 = s1;
        ctx.w = w & ((1usize << ctx.swidth) * PWX_SIMPLE - 1);
    }
}

/// BlockMix variant used by the main SMix loops: pwxform over the whole
/// `r`-block, then finish remaining 64-byte chunks with Salsa20.
fn blockmix_pwxform(b: &mut [u32], s: &mut [u32], ctx: &mut PwxformCtx, r: usize) {
    let mut x = [0u32; PWX_WORDS];
    // How many pwxform-sized chunks fit in a 128·r-byte block.
    let r1 = 128 * r / PWX_BYTES;

    blkcpy(&mut x, &b[(r1 - 1) * PWX_WORDS..r1 * PWX_WORDS]);

    for i in 0..r1 {
        if r1 > 1 {
            blkxor(&mut x, &b[i * PWX_WORDS..(i + 1) * PWX_WORDS]);
        }
        pwxform(&mut x, s, ctx);
        blkcpy(&mut b[i * PWX_WORDS..(i + 1) * PWX_WORDS], &x);
    }

    // After pwxform, mix leftover salsa blocks (classic BlockMix tail).
    let mut i = (r1 - 1) * PWX_BYTES / 64;
    salsa20(&mut b[i * 16..i * 16 + 16], ctx.salsa20_rounds);

    i += 1;
    while i < 2 * r {
        // `split_at_mut` lets us XOR against the previous sub-block without
        // tripping the borrow checker (two mutable views of `b`).
        let (left, right) = b.split_at_mut(i * 16);
        let prev = &left[(i - 1) * 16..i * 16];
        let cur = &mut right[..16];
        blkxor(cur, prev);
        salsa20(cur, ctx.salsa20_rounds);
        i += 1;
    }
}

/// Extract the integer used for data-dependent indexing (last salsa block's
/// first word — same convention as scrypt's `Integerify`).
fn integerify(b: &[u32], r: usize) -> u32 {
    b[(2 * r - 1) * 16]
}

/// Largest power of two ≤ `x` (clear lowest set bit until one bit remains).
fn p2floor(mut x: u32) -> u32 {
    loop {
        let y = x & (x.wrapping_sub(1));
        if y == 0 {
            return x;
        }
        x = y;
    }
}

/// Map `x` into `[0, i)` the way scrypt/yescrypt do during the V-fill loop
/// (when `i` is not yet a power of two).
fn wrap(x: u32, i: u32) -> u32 {
    let n = p2floor(i);
    (x & (n - 1)) + (i - n)
}

/// First SMix1 pass: treat the S-box buffer itself as `V` (`r == 1`) and mix
/// with plain [`blockmix_salsa`]. This *initializes* the S-boxes before the
/// main pwxform-based loops.
fn smix1_sbox(b: &mut [u32], n: u32, s: &mut [u32], x: &mut [u32], ctx: &mut PwxformCtx) {
    const R: usize = 1;
    let s_words = 32 * R;

    // Bytes → salsa SIMD word order (le32dec + unshuffle).
    for k in 0..2 * R {
        for i in 0..16 {
            x[k * 16 + i] = le32dec_word(b[k * 16 + (i * 5 % 16)]);
        }
    }

    // With r == 1 the v1.0 pre-loop over k in 1..r is empty.

    for i in 0..n {
        let i = i as usize;
        blkcpy(&mut s[i * s_words..(i + 1) * s_words], &x[..s_words]);

        if i > 1 {
            let j = wrap(integerify(&x[..s_words], R), i as u32) as usize;
            blkxor(&mut x[..s_words], &s[j * s_words..(j + 1) * s_words]);
        }

        blockmix_salsa(&mut x[..s_words], ctx.salsa20_rounds);
    }

    // Write back: salsa SIMD order → host words (le32enc + shuffle).
    for k in 0..2 * R {
        for i in 0..16 {
            b[k * 16 + (i * 5 % 16)] = le32enc_word(x[k * 16 + i]);
        }
    }
}

/// SMix1: fill `V[0..N)` with successive BlockMix outputs (ROAM-hard store).
///
/// After this, `V` holds `N` snapshots of the working state. Later SMix2
/// passes jump around in `V` using data-dependent indices.
fn smix1(
    b: &mut [u32],
    r: usize,
    n: u32,
    v: &mut [u32],
    x: &mut [u32],
    s: &mut [u32],
    ctx: &mut PwxformCtx,
) {
    let s_words = 32 * r;

    for k in 0..2 * r {
        for i in 0..16 {
            x[k * 16 + i] = le32dec_word(b[k * 16 + (i * 5 % 16)]);
        }
    }

    // v1.0 warm-up: BlockMix each 128-byte sub-block once before the V loop.
    if ctx.version != Version::V0_5 {
        for k in 1..r {
            let (left, right) = x.split_at_mut(k * 32);
            blkcpy(&mut right[..32], &left[(k - 1) * 32..k * 32]);
            blockmix_pwxform(&mut right[..32], s, ctx, 1);
        }
    }

    for i in 0..n {
        let i = i as usize;
        blkcpy(&mut v[i * s_words..(i + 1) * s_words], &x[..s_words]);

        if i > 1 {
            let j = wrap(integerify(&x[..s_words], r), i as u32) as usize;
            blkxor(&mut x[..s_words], &v[j * s_words..(j + 1) * s_words]);
        }

        blockmix_pwxform(&mut x[..s_words], s, ctx, r);
    }

    for k in 0..2 * r {
        for i in 0..16 {
            b[k * 16 + (i * 5 % 16)] = le32enc_word(x[k * 16 + i]);
        }
    }
}

/// SMix2: `nloop` random-access passes over `V`.
///
/// When `nloop == 2` the C reference disables the write-back into `V`
/// (read-only random accesses). Otherwise each visit updates `V[j]`.
#[allow(clippy::too_many_arguments)]
fn smix2(
    b: &mut [u32],
    r: usize,
    n: u32,
    nloop: u32,
    v: &mut [u32],
    x: &mut [u32],
    s: &mut [u32],
    ctx: &mut PwxformCtx,
) {
    let s_words = 32 * r;

    for k in 0..2 * r {
        for i in 0..16 {
            x[k * 16 + i] = le32dec_word(b[k * 16 + (i * 5 % 16)]);
        }
    }

    for _ in 0..nloop {
        // `n` is a power of two, so `& (n - 1)` is a cheap modulo.
        let j = (integerify(&x[..s_words], r) & (n - 1)) as usize;
        blkxor(&mut x[..s_words], &v[j * s_words..(j + 1) * s_words]);
        if nloop != 2 {
            blkcpy(&mut v[j * s_words..(j + 1) * s_words], &x[..s_words]);
        }
        blockmix_pwxform(&mut x[..s_words], s, ctx, r);
    }

    for k in 0..2 * r {
        for i in 0..16 {
            b[k * 16 + (i * 5 % 16)] = le32enc_word(x[k * 16 + i]);
        }
    }
}

/// Full SMix sequence used by yespower:
///
/// 1. `smix1_sbox` — init S-boxes using salsa BlockMix  
/// 2. `smix1` — fill the big `V` array  
/// 3. `smix2` (RW) + `smix2` (mostly RO) — random walks over `V`
fn smix(
    b: &mut [u32],
    r: usize,
    n: u32,
    v: &mut [u32],
    x: &mut [u32],
    s: &mut [u32],
    ctx: &mut PwxformCtx,
) {
    // Loop counts match the C reference's even-rounding of N/3.
    let mut nloop_all = n.div_ceil(3);
    let mut nloop_rw = nloop_all;

    nloop_all += 1;
    nloop_all &= !1u32; // force even
    if ctx.version == Version::V0_5 {
        nloop_rw &= !1u32;
    } else {
        nloop_rw += 1;
        nloop_rw &= !1u32;
    }

    // First loop uses S as V (S-box init via salsa).
    smix1_sbox(b, (ctx.sbytes / 128) as u32, s, x, ctx);
    smix1(b, r, n, v, x, s, ctx);
    smix2(b, r, n, nloop_rw, v, x, s, ctx);
    smix2(b, r, n, nloop_all - nloop_rw, v, x, s, ctx);
}

/// Compute yespower(src, params) → 256-bit hash.
///
/// Returns [`Error::InvalidParams`] when `n` / `r` are outside the ranges
/// accepted by the Openwall reference (power-of-two `n` in
/// `1024..=512*1024`, `r` in `8..=32`).
pub fn yespower(src: &[u8], params: &Params<'_>) -> Result<[u8; 32], Error> {
    let version = params.version;
    let n = params.n;
    let r = params.r;
    let pers = params.pers;

    // `(n & (n - 1)) != 0` is the classic "not a power of two" bit trick.
    if !(1024..=512 * 1024).contains(&n) || !(8..=32).contains(&r) || (n & (n - 1)) != 0 || r < RMIN
    {
        return Err(Error::InvalidParams);
    }

    let r_usz = r as usize;
    let b_size = 128 * r_usz;
    // B: working block · V: N snapshots of B · X: scratch · S: pwxform S-boxes
    let mut b_bytes = vec![0u8; b_size];
    let mut v = vec![0u32; (b_size / 4) * n as usize];
    let mut x = vec![0u32; b_size / 4];

    // Version-specific Salsa / pwxform / S-box sizes (see Openwall docs).
    let (salsa20_rounds, pwx_rounds, swidth, sbytes) = match version {
        Version::V0_5 => (
            8u32,
            PWX_ROUNDS_0_5,
            SWIDTH_0_5,
            2 * swidth_to_sbytes1(SWIDTH_0_5),
        ),
        Version::V1_0 => (
            2u32,
            PWX_ROUNDS_1_0,
            SWIDTH_1_0,
            3 * swidth_to_sbytes1(SWIDTH_1_0),
        ),
    };

    let mut s = vec![0u32; sbytes / 4];
    let swidth_pairs = (1usize << swidth) * PWX_SIMPLE;

    let mut ctx = PwxformCtx {
        version,
        salsa20_rounds,
        pwx_rounds,
        swidth,
        sbytes,
        smask: swidth_to_smask(swidth),
        // Three contiguous S-box windows inside `s`.
        s0: 0,
        s1: swidth_pairs,
        s2: swidth_pairs * 2,
        w: 0,
    };

    // --- Stage 1: derive initial B from src ---------------------------------
    let mut sha_bytes = sha256(src);

    // Salt choice is a key behavioural difference between versions.
    let salt: &[u8] = match version {
        Version::V0_5 => src,
        Version::V1_0 => pers.unwrap_or(&[]),
    };

    pbkdf2_sha256(&sha_bytes, salt, 1, &mut b_bytes);

    let mut b = words_from_bytes(&b_bytes);
    // Keep the first 32 bytes of B — later used as the "password" for the
    // final KDF / HMAC (mirrors the C code's `sha256` local buffer).
    sha_bytes = {
        let w = &b[..8];
        let mut out = [0u8; 32];
        for (i, word) in w.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        out
    };

    // --- Stage 2: RAM-hard mix ----------------------------------------------
    smix(&mut b, r_usz, n, &mut v, &mut x, &mut s, &mut ctx);

    // --- Stage 3: finalize to 32 bytes --------------------------------------
    let dst = match version {
        Version::V0_5 => {
            let b_as_bytes = bytes_from_words(&b);
            let mut dk = [0u8; 32];
            pbkdf2_sha256(&sha_bytes, &b_as_bytes, 1, &mut dk);
            // Optional personalization: HMAC(dk, pers) then SHA-256.
            if let Some(pers) = pers {
                let h = hmac_sha256(&dk, pers);
                sha256(&h)
            } else {
                dk
            }
        }
        Version::V1_0 => {
            let b_as_bytes = bytes_from_words(&b);
            // Last 64 bytes of B are the HMAC key; message is the saved
            // first-32-bytes-of-B from before SMix.
            let key = &b_as_bytes[b_size - 64..];
            hmac_sha256(key, &sha_bytes)
        }
    };

    Ok(dst)
}

#[cfg(test)]
mod tests;
