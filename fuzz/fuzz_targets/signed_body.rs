#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| dht_next::testing::fuzz_signed_body(body));
