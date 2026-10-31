//! Fuzz target `cx_open`: see `crypthix_fuzz_harness::cx_open`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::cx_open(data));
