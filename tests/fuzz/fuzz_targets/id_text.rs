//! Fuzz target `id_text`: see `crypthix_fuzz_harness::id_text`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::id_text(data));
