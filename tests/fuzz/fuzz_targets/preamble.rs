//! Fuzz target `preamble`: see `crypthix_fuzz_harness::preamble`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::preamble(data));
