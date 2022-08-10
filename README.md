# rfsb509-rs
A Rust implementation of the RFSB-509 hash function [1].

# Overview

RFSB is a _syndrome based_ hash function, a form of cryptographic hash function whose security rests on the hardness of decoding linear codes. Hashing essentially consists in computing a matrix-vector product (and a quick modular reduction by 509) and is therefore very fast. 

A final "filter" of SHA-256 is applied to the output, both to pro-actively defeat any algebraic flaw in RFSB, and to help with the theoretical analysis (under assumptions that SHA-256 is well-behaved). 

# Limitations and caveats

**Security:** While no efficient attack is currently known against RFSB509, it is not widely used and this particular implementation has not been independentely reviewed for bugs, side-channel issues, or compatibility with other implementations of RFSB509, and it has not be extensively tested. Use at your own risk. 

**Performance:** This is a straightforward implementation from the paper's description, which makes no use of clever optimisations. In the current state of affairs, this implementation of RFSB509 is about 10 times slower than SHA256. This is not an issue for experimenting with the primitive, or building from it; but this may be disappointing. We welcome suggestions to make it faster!

**Portability**: The current implementation uses x64-64 AES and SHA intrinsics for operation.

**Constness**: The library is currently not `const`. To make it so woule require a `const` implementation of AES and SHA (which would probably not be able to use intrisics) and the `const` stabilisation of several array-related operations.

# Benchmarking

Run `RUSTFLAGS="-C target-cpu=native" cargo bench` in a terminal.

# Usage

```rust

fn main() {
    use rfsb509::hash;

    let some_data = b"A Rust implementation of the RFSB-509 hash function";

    println!("{:?}", hash(some_data));
}

```

# References

[1] Daniel J. Bernstein, Tanja Lange, Christiane Peters, Peter Schwabe. 
Really fast syndrome-based hashing. AFRICACRYPT 2011: p 134-152. [https://eprint.iacr.org/2011/074](paper) [https://cryptojedi.org/peter/data/africacrypt-20110705.pdf](slides)
