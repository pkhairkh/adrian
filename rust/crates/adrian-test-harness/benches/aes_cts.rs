//! Criterion benchmark — AES-256-CBC-CTS encrypt/decrypt throughput.
//!
//! Measures the raw AES-256-CBC-CTS (RFC 2040 §6 CS3 variant, RFC 3962
//! §5.3) encrypt and decrypt operations exposed by
//! `adrian_kdc::crypto::{aes256_cts_encrypt, aes256_cts_decrypt}`. The
//! benchmark covers three plaintext sizes:
//!
//! - 16 bytes (one AES block — the ECB special case)
//! - 64 bytes (four full blocks — standard CBC)
//! - 80 bytes (five blocks with a partial last block — the CS3 swap
//!   path)
//!
//! The bench is sync — no tokio runtime needed.

use adrian_kdc::crypto::{self, Aes256Key};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn make_key() -> Aes256Key {
    crypto::derive_aes256_key(b"bench-password", b"bench-salt")
}

fn bench_encrypt(c: &mut Criterion) {
    let key = make_key();
    let sizes: &[(usize, &str)] = &[
        (16, "16B (1 block)"),
        (64, "64B (4 blocks)"),
        (80, "80B (5 blocks, partial)"),
    ];
    let mut group = c.benchmark_group("aes256_cts_encrypt");
    for (size, label) in sizes {
        let plaintext = vec![0xABu8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(label), &plaintext, |b, pt| {
            b.iter(|| {
                let ct = crypto::aes256_cts_encrypt(black_box(&key), black_box(pt)).unwrap();
                black_box(ct);
            });
        });
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let key = make_key();
    let sizes: &[(usize, &str)] = &[
        (16, "16B (1 block)"),
        (64, "64B (4 blocks)"),
        (80, "80B (5 blocks, partial)"),
    ];
    let mut group = c.benchmark_group("aes256_cts_decrypt");
    for (size, label) in sizes {
        let plaintext = vec![0xABu8; *size];
        let ciphertext = crypto::aes256_cts_encrypt(&key, &plaintext).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(label), &ciphertext, |b, ct| {
            b.iter(|| {
                let pt = crypto::aes256_cts_decrypt(black_box(&key), black_box(ct)).unwrap();
                black_box(pt);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
