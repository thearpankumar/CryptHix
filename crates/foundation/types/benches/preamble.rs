//! Benchmarks for the 20-byte preamble. Run with `cargo bench -p crypthix-types --bench preamble`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use crypthix_types::preamble::Preamble;
use crypthix_types::registry::FileType;

fn benches(c: &mut Criterion) {
    let preamble = Preamble::new(FileType::Keyring, 64).expect("within cap");
    let mut file = preamble.to_bytes().to_vec();
    file.resize(Preamble::LEN + 64, 0);
    c.bench_function("preamble/parse", |b| {
        b.iter(|| Preamble::parse(black_box(&file)));
    });
    c.bench_function("preamble/to_bytes", |b| {
        b.iter(|| black_box(preamble).to_bytes());
    });
}

criterion_group!(preamble, benches);
criterion_main!(preamble);
