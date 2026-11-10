//! Benchmarks of the chunker: FastCDC over 64 MiB in memory and through a reader.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use crypthix_core::blob::ObjectClass;
use crypthix_core::chunk::{Chunks, GearTable, StreamChunker};
use crypthix_crypto::key::{KdfKey, XofKey};
use crypthix_crypto::mac;
use crypthix_types::id::VaultId;

const LEN: usize = 64 << 20;

fn setup() -> (GearTable, Vec<u8>) {
    let seed = KdfKey::random().expect("getrandom works");
    let vault_id = VaultId::try_from_bytes([1; 16]).expect("non-zero");
    let gear = GearTable::derive(&seed, &vault_id).expect("derives");
    let mut data = vec![0u8; LEN];
    mac::xof(&XofKey::random().expect("getrandom works"), &mut data);
    (gear, data)
}

fn chunking(c: &mut Criterion) {
    let (gear, data) = setup();
    let mut group = c.benchmark_group("chunking");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(LEN as u64));
    group.bench_function("chunks/64MiB", |b| {
        b.iter(|| Chunks::new(&gear, ObjectClass::Ordinary, black_box(&data)).count());
    });
    group.bench_function("stream/64MiB", |b| {
        b.iter(|| {
            let mut chunker =
                StreamChunker::new(&gear, ObjectClass::Ordinary, black_box(data.as_slice()))
                    .expect("window");
            let mut count = 0usize;
            while chunker.next_chunk().expect("reads").is_some() {
                count += 1;
            }
            count
        });
    });
    group.finish();
}

criterion_group!(benches, chunking);
criterion_main!(benches);
