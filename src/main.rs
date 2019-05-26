extern crate crypto;

use crypto::{aes::KeySize::KeySize128, aesni, symmetriccipher::BlockEncryptor, util};

use std::convert::AsMut;

// Helper: get a fixed-sized array from a slice
fn copy_into_array<A: Default + AsMut<[T]>, T: Copy>(slice: &[T]) -> A {
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
    a
}

// Generate the RFSB-509 matrix
fn genmatrix() -> [u8; 16384] {
    // All zero AES key
    let zero_key = [0x00; 16];

    let mut matrix = vec![];
    let mut result = [0x00; 16384];

    if util::supports_aesni() {
        println!("AES-NI supported");

        let enc = aesni::AesNiEncryptor::new(KeySize128, &zero_key);

        for j in 0..=255 {
            let mut blocks = vec![];

            for k in 0..4 {
                let mut tmp = [0x00 as u8; 16];
                let mut col = [0x00 as u8; 16];

                col[0] = k;
                col[1] = j;

                enc.encrypt_block(&col, &mut tmp);
                blocks.push(tmp);
            }

            let first = blocks[0][0] ^ (blocks[3][15] >> 5);
            blocks[3][15] &= 31;
            blocks[0][0] = first;

            matrix.push(blocks);
        }
    } else {
        println!("AES-NI not supported");
        // TODO: use a non-NI AES
    }

    let mut ctr = 0;
    for line in matrix {
        for block in line {
            for entry in &block {
                result[ctr] = *entry;
                ctr += 1;
            }
        }
    }

    result
}

// Store the value `v` as a little endian byte sequence
// Note: there might be a built-in method to do that
fn store_littleendian(v: u64) -> [u8; 8] {
    let mut x = [0x00; 8];
    let mut u = v;
    for i in 0..8 {
        x[i] = (u % 256) as u8;
        u >>= 8;
    }
    x
}

// Load `x` as a little endian u64
// Note: there might be a built-in method to do that
fn load_littleendian(x: [u8; 8]) -> u64 {
    let v: Vec<u64> = x.iter().map(|&x| u64::from(x)).collect();
    let mut res = 0;

    for i in 0..8 {
        res += v[i] << (8 * i);
    }

    res
}

// Load a column from the generating matrix
fn column_load(pos: u64, matrix: &[u8; 16384]) -> [u64; 10] {
    let mut x = [0; 10];
    let p = pos << 6;

    for i in 0..10 {
        let idx = (p as usize) + i * 8;
        x[i] = load_littleendian(copy_into_array(&matrix[idx..idx + 8]));
    }

    x
}

// Multiplicating column (by shifting)
fn column_mulx128(c: &mut [u64; 10]) {
    for i in (9..1).rev() {
        c[i] = c[i - 2];
    }
    c[0] = 0;
    c[1] = 0;
}

// Adding columns (by xoring)
fn column_add(r: &mut [u64; 10], x: &[u64; 10]) {
    for i in 0..10 {
        r[i] ^= x[i];
    }
}

// Modular reduction
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

// hash one block
// cur_state: state (used as an output as well)
// b: data to be processed (will be proceesed as 48-byte blocks)
// matrix: the generating matrix
// the function returns the number of remaining bytes in b not consumed (when b is not a multiple of 48 bytes)
fn hash_block(cur_state: &mut [u8; 64], b: &[u8], matrix: &[u8; 16384]) -> usize {
    let mut state = [0; 64];

    // Clone `cur_state` into `state`
    state[..64].clone_from_slice(&cur_state[..64]);

    let mut idx = b.len();
    let mut b_idx = 0;

    while idx >= 48 {
        let positions: Vec<u64> = (0..112)
            .map(|i| match i {
                0..=63 => u64::from(state[i]),
                64..=111 => u64::from(b[b_idx + i - 64]),
                _ => panic!(),
            })
            .collect();

        let mut v = column_load(positions[0], matrix);

        for p in positions.iter().skip(1) {
            column_mulx128(&mut v);
            let t = column_load(*p, matrix);
            column_add(&mut v, &t);
            column_modx509(&mut v);
        }

        for i in 0..8 {
            let sle = store_littleendian(v[i]);
            for j in 0..8 {
                state[8 * i + j] = sle[j];
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
fn hash(input: &[u8], matrix: &[u8; 16384]) -> [u8; 64] {
    let mut state = [0x00; 64];

    let remaining = hash_block(&mut state, input, &matrix);

    if remaining > 0 {
        // Last block is padded with zeros
        let mut last_block = [0; 48];

        for i in 0..remaining {
            last_block[i] = state[state.len() - remaining + i]
        }

        hash_block(&mut state, &last_block[..], &matrix);
    }

    state
}

fn main() {
    let matrix = genmatrix();

    let test_string = b"Hi there how is life?";

    let result = hash(&test_string[..], &matrix);

    // result now contains the hashed block.
}
