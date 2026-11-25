#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Network Scope desktop binary. Release builds use the Windows GUI subsystem so a
//! double-click opens no console; the program itself is `network_scope::run`.

fn main() -> network_scope::RunResult {
    network_scope::run()
}
