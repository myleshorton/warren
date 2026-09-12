#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| dht_next::testing::fuzz_lifecycle(data));
