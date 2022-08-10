use std::arch::x86_64::{_mm_aesenc_si128, _mm_aesenclast_si128, _mm_xor_si128};
use std::mem::{transmute};

use crate::precomputed::PRECOMPUTED_ROUND_KEYS;

/* Implementation of AES using AES-NI, specialized for the zero key.
 */
#[target_feature(enable = "aes")]
pub unsafe fn aesenc(input: u128) -> u128 {
    let keys = PRECOMPUTED_ROUND_KEYS;

    let mut b = transmute(input);
    b = _mm_xor_si128(b, transmute(keys[0]));
    b = _mm_aesenc_si128(b, transmute(keys[1]));
    b = _mm_aesenc_si128(b, transmute(keys[2]));
    b = _mm_aesenc_si128(b, transmute(keys[3]));
    b = _mm_aesenc_si128(b, transmute(keys[4]));
    b = _mm_aesenc_si128(b, transmute(keys[5]));
    b = _mm_aesenc_si128(b, transmute(keys[6]));
    b = _mm_aesenc_si128(b, transmute(keys[7]));
    b = _mm_aesenc_si128(b, transmute(keys[8]));
    b = _mm_aesenc_si128(b, transmute(keys[9]));
    b = _mm_aesenclast_si128(b, transmute(keys[10]));

    transmute(b)
}

