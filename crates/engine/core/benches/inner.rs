//! Benchmarks of a chunk's inner plaintext: compress and pad, then check and decompress, for a
//! 256 KiB chunk that compresses and one that does not.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use crypthix_core::blob::ObjectClass;
use crypthix_core::compress::{Compressor, Decompressor};
use crypthix_core::inner::{self, Comp};
use crypthix_crypto::key::XofKey;
use crypthix_crypto::mac;

const LEN: usize = 256 << 10;

fn inner(c: &mut Criterion) {
    let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog "
        .iter()
        .copied()
        .cycle()
        .take(LEN)
        .collect();
    let mut random = vec![0u8; LEN];
    mac::xof(&XofKey::random().expect("getrandom works"), &mut random);
    let mut compressor = Compressor::new().expect("context");
    let mut decompressor = Decompressor::new();
    let mut group = c.benchmark_group("inner");
    group.throughput(Throughput::Bytes(LEN as u64));
    for (name, chunk) in [("compressible", &text), ("random", &random)] {
        group.bench_function(format!("encode/{name}"), |b| {
            b.iter(|| compressor.encode_chunk(black_box(chunk), ObjectClass::Ordinary));
        });
        let encoded = compressor
            .encode_chunk(chunk, ObjectClass::Ordinary)
            .expect("encodes");
        group.bench_function(format!("decode/{name}"), |b| {
            b.iter(|| {
                let view = inner::decode_inner(black_box(&encoded)).expect("well formed");
                match view.comp() {
                    Comp::Zstd => decompressor
                        .decode(view.payload(), LEN as u64)
                        .map(|plain| plain.len())
                        .expect("decodes"),
                    _ => view.payload().len(),
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, inner);
criterion_main!(benches);
