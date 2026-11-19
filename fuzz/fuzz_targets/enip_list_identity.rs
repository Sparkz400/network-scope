#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| network_scope::fuzz::enip_list_identity(data));
