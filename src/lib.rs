mod constants;
mod precomputed;
mod primitives;

use crate::{constants::*, precomputed::*, primitives::aesenc};

use generic_array::GenericArray;
use std::convert::AsMut;

// Helper: get a fixed-sized array from a slice
fn copy_into_array<A: Default + AsMut<[T]>, T: Copy>(slice: &[T]) -> A {
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
    a
}

// Multiplicating column (by shifting)
#[inline]
fn column_mulx128(c: &mut [u64; 10]) {
    c.rotate_right(2);
    c[0] = 0;
    c[1] = 0;
}

// Adding columns (by xoring)
#[inline]
fn column_add(r: &mut [u64; 10], x: [u64; 10]) {
    for j in 0..9 {
        r[j] ^= x[j];
    }
}

// Modular reduction
#[inline]
fn column_modx509(c: &mut [u64; 10]) {
    c[0] ^= c[7] >> 61;
    c[0] ^= c[8] << 3;
    c[1] ^= c[8] >> 61;
    c[1] ^= c[9] << 3;
    c[2] ^= c[9] >> 61;
    c[7] &= 0x1fff_ffff_ffff_ffff;
    c[8] = 0;
    c[9] = 0;
}

// Load a column from the generating matrix
fn column_load(pos: u8, matrix: &[u8; MATRIX_SIZE]) -> [u64; 10] {
    let p = (pos as usize) << 6;

    let mut x = [0; 10];
    for i in 0..10 {
        let idx = p | (i << 3);
        x[i] = u64::from_le_bytes(copy_into_array(&matrix[idx..idx + 8]));
    }

    x
}

fn copy_block_at(input: [u8; BLOCK_SIZE], output: &mut [u8; MATRIX_SIZE], offset: usize) {
    let mut ctr = 0;
    while ctr < BLOCK_SIZE {
        output[offset + ctr] = input[ctr];
        ctr += 1;
    }
}

// Generate the RFSB-509 matrix
// This function cannot be const because there is currently no
// const AES implementation in rust. However, this may happen one
// day and this day we'd be frustrated if we can't use 'for' in
// const fn
//
pub fn genmatrix() -> [u8; MATRIX_SIZE] {
    let mut result = [0u8; MATRIX_SIZE];

    let mut j = 0;
    let mut k = 0;

    while j < MATRIX_ROWS {
        let offset = (j as u128) << 8;

        let mut blocks = [
            unsafe { aesenc(offset).to_le_bytes() },
            unsafe { aesenc(offset | 1).to_le_bytes() },
            unsafe { aesenc(offset | 2).to_le_bytes() },
            unsafe { aesenc(offset | 3).to_le_bytes() },
        ];

        // Reduction mod 509
        let first = blocks[0][0] ^ (blocks[3][15] >> 5);
        let last = blocks[3][15] & 31;
        blocks[0][0] = first;
        blocks[3][15] = last;

        for i in 0..4 {
            copy_block_at(blocks[i], &mut result, k);    
            k += BLOCK_SIZE;
        }

        j += 1;
    }

    result
}

// hash one block
// cur_state: state (used as an output as well)
// b: data to be processed (will be proceesed as 48-byte blocks)

// the function returns the number of remaining bytes in b not consumed (when b is not a multiple of 48 bytes)
fn hash_blocks(cur_state: &mut [u8; 128], b: &[u8]) -> usize {
    let mut state = [0u8; 64];
    let mut positions = [0u8; 128];

    // Clone `cur_state` into `state`
    state[..64].clone_from_slice(&cur_state[..64]);

    let mut idx = b.len();
    let mut b_idx = 0;

    while idx >= 48 {
        positions[..64].copy_from_slice(&state[..64]);

        for i in 64..112 {
            positions[i] = b[b_idx + i - 64]
        }

        let mut v = column_load(positions[0], &PRECOMPUTED_MATRIX);

        for i in 1..112 {
            column_mulx128(&mut v);
            column_add(&mut v, column_load(positions[i], &PRECOMPUTED_MATRIX));
            column_modx509(&mut v);
        }

        for i in 0..8 {
            let xi_bytes = v[i].to_le_bytes();
            let offset = i << 3;
            for j in 0..8 {
                state[offset | j] = xi_bytes[j];
        }
        }

        b_idx += 48;
        idx -= 48;
    }

    // Clone `state` into `cur_state`
    cur_state[..64].clone_from_slice(&state[..64]);

    // Return the number of remaining bytes
    idx
}

// RFSB-509 hash function
pub fn hash(input: &[u8]) -> [u8; 32] {
    let mut state = [0u8; 128];

    // Main operation
    let remaining = hash_blocks(&mut state, input);

    // Padding for the last block
    let padlen = if remaining <= 40 { 48 } else { 96 };
    let mut pad = vec![0; padlen];
    let inlen = input.len();
    for i in 0..remaining {
        pad[i] = input[inlen - remaining + i];
    }
    for i in (padlen - 8)..padlen {
        pad[i] = ((inlen >> (8 * (i - 40))) & 0xff) as u8;
    }

    hash_blocks(&mut state, &pad);

    // Filter output by SHA256
    state[64] = 0x80;
    state[126] = 0x02;

    let mut result = PRECOMPUTED_SHA256_IV;
    let data = [
        *GenericArray::from_slice(&state[..64]),
        *GenericArray::from_slice(&state[64..]),
    ];
    sha2::compress256(&mut result, &data);

    unsafe { std::mem::transmute(result) }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn gen_matrix() {
        let matrix = genmatrix();

        assert_eq!(matrix, PRECOMPUTED_MATRIX);
    }

    #[test]
    fn test_hash() {
        let input1 = b"Hello world!";
        let input2 = b"Hello worlb!";
        let result1 = hash(input1);
        let result2 = hash(input2);

        assert_ne!(result1, result2);
    }
}
