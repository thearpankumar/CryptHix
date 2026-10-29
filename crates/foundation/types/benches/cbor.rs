//! Benchmarks for the strict CBOR codec: validating large and deep documents, and encoding a
//! typical map. Run with `cargo bench -p crypthix-types --bench cbor`.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use crypthix_types::cbor::{Document, Encoder, Limits};
use crypthix_types::format_error::FormatError;

/// An array of 4096 byte strings of 256 bytes each: about 1 MiB.
fn large_document() -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder
        .array(|items| {
            for n in 0..4096u32 {
                items.bytes(&[n.to_le_bytes()[0]; 256]);
            }
            Ok(())
        })
        .expect("within limits");
    encoder.finish(&Limits::FORMAT_0).expect("canonical")
}

/// Maps nested to the format 0 depth limit, each with a few scalar entries.
fn deep_document() -> Vec<u8> {
    fn level(encoder: &mut Encoder, depth: usize) -> Result<(), FormatError> {
        encoder.map(|map| {
            map.entry(1, |value| {
                value.uint(42);
                Ok(())
            })?;
            map.entry(2, |value| value.text("label"))?;
            if depth > 1 {
                map.entry(3, |value| level(value, depth - 1))?;
            }
            Ok(())
        })
    }
    let mut encoder = Encoder::new();
    level(&mut encoder, Limits::FORMAT_0.max_depth()).expect("within limits");
    encoder.finish(&Limits::FORMAT_0).expect("canonical")
}

/// Encodes a map shaped like a small manifest entry.
fn encode_map() -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder
        .map(|map| {
            map.entry(1, |value| {
                value.bytes(&[7; 16]);
                Ok(())
            })?;
            map.entry(2, |value| {
                value.uint(1_700_000_000);
                Ok(())
            })?;
            map.entry(3, |value| value.text("notes/2026/plan.md"))?;
            map.entry(-1, |value| {
                value.bytes(&[9; 32]);
                Ok(())
            })
        })
        .expect("valid map");
    encoder.finish(&Limits::FORMAT_0).expect("canonical")
}

fn benches(c: &mut Criterion) {
    let large = large_document();
    let mut group = c.benchmark_group("cbor");
    group.throughput(Throughput::Bytes(large.len() as u64));
    group.bench_function("parse_1mib", |b| {
        b.iter(|| Document::parse(black_box(&large), &Limits::FORMAT_0));
    });
    group.finish();

    let deep = deep_document();
    c.bench_function("cbor/parse_deep", |b| {
        b.iter(|| Document::parse(black_box(&deep), &Limits::FORMAT_0));
    });
    c.bench_function("cbor/encode_map", |b| b.iter(encode_map));
}

criterion_group!(cbor, benches);
criterion_main!(cbor);
