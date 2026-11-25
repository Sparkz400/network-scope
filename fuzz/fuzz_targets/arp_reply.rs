#![no_main]
// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
libfuzzer_sys::fuzz_target!(|data: &[u8]| network_scope::fuzz::arp_reply(data));
