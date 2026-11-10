//! Fuzz target `chunker`: see `crypthix_fuzz_harness::chunker`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::chunker(data));
