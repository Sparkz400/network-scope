// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `wol MAC [--broadcast IP] [--dry-run]`: Wake-on-LAN, one UDP broadcast "magic packet" (port 9).
//! It is a send, so it takes its token from the rate gate with the packet kind `wake-on-lan`,
//! `--dry-run` lists it, and the scope guard checks a directed broadcast address (the limited
//! broadcast 255.255.255.255 never leaves the network segment). Only this command and the
//! desktop button send it; a scan never does.
use crate::{
    core::Gate,
    sendlog::{self, SentLog},
    ui::{Ctx, dryrun, guard, output, progress},
    wol,
};
use std::{net::Ipv4Addr, sync::Arc};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let [mac_text] = ctx.pos.as_slice() else {
        return Err("Usage: wol MAC [--broadcast IPV4]".into());
    };
    let mac_text = mac_text.clone();
    let mac = wol::parse_mac(&mac_text)?;
    let destination: Ipv4Addr = match ctx.opts.get("broadcast") {
        Some(text) => text
            .parse()
            .map_err(|_| format!("{text}: --broadcast must be an IPv4 address"))?,
        None => Ipv4Addr::BROADCAST,
    };
    wol::check_destination(destination)?;
    if dryrun::requested(&ctx.opts) {
        return dryrun::wol_plan(&ctx.opts, destination);
    }
    if !guard::enforce(ctx, &wol::guard_addresses(destination))? {
        return Ok(());
    }
    let log = Arc::new(SentLog::new());
    let gate = Gate::new(1000).with_log(log.clone());
    wol::send(mac, destination, &gate)?;
    progress(
        &ctx.opts,
        format_args!(
            "Sent a magic packet for {mac_text} to {destination}:{}",
            wol::PORT
        ),
    );
    if ctx.opts.contains_key("sent-log") {
        output(&sendlog::format_table(&log.snapshot()), &ctx.opts)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ui::{ExitCode, run, testutil::args};

    #[test]
    fn bad_macs_and_public_destinations_are_refused_before_anything_is_sent() {
        for list in [
            vec!["wol"],
            vec!["wol", "not-a-mac"],
            vec!["wol", "00:11:22:33:44:55", "--broadcast", "8.8.8.8"],
            vec!["wol", "00:11:22:33:44:55", "--broadcast", "banana"],
            vec!["wol", "FF:FF:FF:FF:FF:FF"],
        ] {
            assert!(run(&args(&list)).is_err(), "{list:?}");
        }
    }

    #[test]
    fn dry_run_lists_the_packet_and_sends_nothing() {
        let dir = std::env::temp_dir().join(format!("ns-wol-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.txt");
        let status = run(&args(&[
            "wol",
            "00:11:22:33:44:55",
            "--broadcast",
            "192.168.1.255",
            "--dry-run",
            "--output",
            out.to_str().unwrap(),
        ]))
        .unwrap();
        assert_eq!(status, ExitCode::Success);
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.starts_with("DRY RUN: nothing was sent."), "{text}");
        assert!(
            text.contains("wake-on-lan") && text.contains("192.168.1.255:9"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
