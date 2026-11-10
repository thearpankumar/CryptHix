//! Fuzz target `decompress`: see `crypthix_fuzz_harness::decompress`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::decompress(data));
