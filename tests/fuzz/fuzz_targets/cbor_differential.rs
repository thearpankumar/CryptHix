//! Fuzz target `cbor_differential`: see `crypthix_fuzz_harness::cbor_differential`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::cbor_differential(data));
