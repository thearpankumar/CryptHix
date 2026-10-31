//! Benchmarks of CX-AEAD and `H` at typical blob and pack sizes.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use crypthix_crypto::aad::Aad;
use crypthix_crypto::cx_aead::{self, NonceKind};
use crypthix_crypto::hash;
use crypthix_crypto::key::SealKey;
use crypthix_crypto::label::{AadLabel, HashLabel};

fn cx_aead(c: &mut Criterion) {
    let key = SealKey::random().expect("getrandom works");
    let aad = Aad::new(AadLabel::BlobData).field(&[1u8; 16]);
    let mut group = c.benchmark_group("cx_aead");
    for size in [4 * 1024, 1024 * 1024] {
        let plaintext = vec![0x5a_u8; size];
        let sealed = cx_aead::seal(&key, &aad, &plaintext, NonceKind::Hedged).expect("seals");
        group.throughput(Throughput::Bytes(u64::try_from(size).expect("fits")));
        group.bench_function(format!("seal/{size}"), |b| {
            b.iter(|| cx_aead::seal(&key, &aad, black_box(&plaintext), NonceKind::Hedged));
        });
        group.bench_function(format!("open/{size}"), |b| {
            b.iter(|| cx_aead::open(&key, &aad, black_box(&sealed)));
        });
    }
    group.finish();
}

fn hash_1mib(c: &mut Criterion) {
    let data = vec![0x5a_u8; 1024 * 1024];
    let mut group = c.benchmark_group("hash");
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("H/1048576", |b| {
        b.iter(|| hash::hash(HashLabel::Blob, black_box(&data)));
    });
    group.finish();
}

criterion_group!(benches, cx_aead, hash_1mib);
criterion_main!(benches);
