//! Fuzz target `cbor_document`: see `crypthix_fuzz_harness::cbor_document`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::cbor_document(data));
