//! Fuzz target `store_key`: see `crypthix_fuzz_harness::store_key`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::store_key(data));
