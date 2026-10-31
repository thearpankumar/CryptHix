//! Fuzz target `verifying_key`: see `crypthix_fuzz_harness::verifying_key`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::verifying_key(data));
