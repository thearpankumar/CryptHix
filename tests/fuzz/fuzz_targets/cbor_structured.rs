//! Fuzz target `cbor_structured`: see `crypthix_fuzz_harness::cbor_structured`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::cbor_structured(data));
