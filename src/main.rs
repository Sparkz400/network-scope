#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod capture;
mod core;
mod devices;
mod gui;
mod monitor;
mod nmap;
mod osfp;
mod ot;
mod otpassive;
mod oui;
mod passive;
mod pcapfile;
mod platform;
mod probes;
mod report;
mod risk;
mod scan;
mod script;
mod service;
mod store;
mod syn;
mod tls;
mod topology;
mod trace;
mod udp;
mod ui;
use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    if cli_args
        .first()
        .is_some_and(|a| !a.starts_with("--screenshot"))
    {
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn AttachConsole(id: u32) -> i32;
                fn GetStdHandle(kind: u32) -> isize;
            }
            if GetStdHandle(-11i32 as u32) == 0 {
                AttachConsole(u32::MAX);
            }
        }
        if let Err(e) = ui::run(&cli_args) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let mut screenshot = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--screenshot" || arg == "--screenshot-path" {
            screenshot = args.next().map(PathBuf::from);
        }
        if let Some(path) = arg.strip_prefix("--screenshot=") {
            screenshot = Some(PathBuf::from(path));
        }
    }
    gui::run(screenshot)
}
