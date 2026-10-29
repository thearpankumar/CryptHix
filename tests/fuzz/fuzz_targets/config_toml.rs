//! Fuzz target `config_toml`: see `crypthix_fuzz_harness::config_toml`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crypthix_fuzz_harness::config_toml(data));
