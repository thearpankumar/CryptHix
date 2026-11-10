//! Fuzz target `inner_plaintext`: see `crypthix_fuzz_harness::inner_plaintext`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::inner_plaintext(data));
