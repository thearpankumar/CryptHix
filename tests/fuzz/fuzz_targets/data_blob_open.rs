//! Fuzz target `data_blob_open`: see `crypthix_fuzz_harness::data_blob_open`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::data_blob_open(data));
