// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Findings from observed control traffic (writes, stop, download, restart).
use crate::{passive::Observation, risk::Severity};
use std::net::IpAddr;

/// Findings from observed control traffic: who is writing to or stopping a controller.
pub fn control_findings(observations: &[Observation]) -> Vec<(Severity, IpAddr, String)> {
    observations
        .iter()
        .filter(|o| o.protocol.ends_with("server (observed)"))
        .filter_map(|o| {
            let traffic = o.fields.get("control_traffic")?;
            let sev = if traffic.contains("Stop")
                || traffic.contains("Download")
                || traffic.contains("Restart")
                || traffic.contains("PLC Control")
                || traffic.contains("Kill")
                || traffic.contains("Remote Reset")
                || traffic.contains("Reset Program")
            {
                Severity::High
            } else {
                Severity::Medium
            };
            Some((
                sev,
                o.ip?,
                format!(
                    "{}: control traffic observed ({traffic}) from {}",
                    o.protocol.trim_end_matches(" (observed)"),
                    o.fields.get("clients").map_or("?", String::as_str)
                ),
            ))
        })
        .collect()
}
