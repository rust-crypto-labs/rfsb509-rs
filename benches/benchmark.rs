use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rfsb509::hash;

pub fn hash_kilobyte_rfsb(c: &mut Criterion) {
    c.bench_function("RFSB 1KB", |b| b.iter(|| hash(black_box(&vec![123u8; 1024]))));
}

pub fn hash_megabyte_rfsb(c: &mut Criterion) {
    c.bench_function("RFSB 1MB", |b| b.iter(|| hash(black_box(&vec![123u8; 1024 * 1024]))));
}

pub fn hash_10megabyte_rfsb(c: &mut Criterion) {
    c.bench_function("RFSB 10MB", |b| b.iter(|| hash(black_box(&vec![123u8; 100*1024 * 1024]))));
}


pub fn hash_kilobyte_sha256(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    c.bench_function("SHA-256 1KB", |b| {
        b.iter(|| {
            let input = vec![123u8; 1024];
            let mut hasher = Sha256::new();
            hasher.update(black_box(&input));
            black_box(hasher.finalize())
        })
    });
}


pub fn hash_megabyte_sha256(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    c.bench_function("SHA-256 1MB", |b| {
        b.iter(|| {
            let input = vec![123u8; 1024*1024];
            let mut hasher = Sha256::new();
            hasher.update(black_box(&input));
            black_box(hasher.finalize())
        })
    });
}


pub fn hash_10megabyte_sha256(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    c.bench_function("SHA-256 100MB", |b| {
        b.iter(|| {
            let input = vec![123u8; 10*1024*1024];
            let mut hasher = Sha256::new();
            hasher.update(black_box(&input));
            black_box(hasher.finalize())
        })
    });
}

criterion_group!(
    benches,
    hash_kilobyte_rfsb,
    hash_kilobyte_sha256,
    hash_megabyte_rfsb,
    hash_megabyte_sha256,
    hash_10megabyte_rfsb,
    hash_10megabyte_sha256
);
criterion_main!(benches);
