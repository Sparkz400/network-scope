//! `update check`: asks GitHub whether a newer release exists and prints the release page and the
//! commands that verify a download. It never downloads or installs anything; see the module
//! documentation of `network_scope_core::update` for exactly what is sent. Nothing contacts
//! GitHub unless this command is run (or the desktop setting "Check for updates on start" is on).
use crate::{
    ui::{Ctx, output, progress},
    update,
};
use std::collections::BTreeMap;

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    match ctx.pos.first().map(String::as_str) {
        Some("check") => {
            progress(
                &ctx.opts,
                "Asking GitHub for the latest release (one HTTPS request; nothing is downloaded or installed)...",
            );
            check_at(&ctx.opts, update::LATEST_URL)
        }
        _ => Err("Use: update check".into()),
    }
}

/// `update check` against `url` (the real endpoint, or an in-process server in the tests).
fn check_at(opts: &BTreeMap<String, String>, url: &str) -> Result<(), String> {
    let current = env!("CARGO_PKG_VERSION");
    let outcome = update::check_at(url, current, update::DEFAULT_TIMEOUT)
        .map_err(|e| format!("Update check failed: {e}"))?;
    output(&update::describe(&outcome, current), opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{run, testutil::args};
    use std::io::{Read, Write};

    /// Serves one answer on a loopback port; returns the URL.
    fn serve(body: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            let _ = c.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        });
        format!("http://127.0.0.1:{port}/latest")
    }

    #[test]
    fn update_check_prints_the_release_and_the_verification_commands() {
        let dir = std::env::temp_dir().join(format!("ns-update-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.txt");
        let opts: BTreeMap<String, String> =
            [("output".to_string(), out.to_str().unwrap().to_string())].into();
        // A release far above the running version.
        check_at(&opts, &serve(r#"{"tag_name":"v99.0.0"}"#)).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.starts_with("Version 99.0.0 is available"), "{text}");
        for want in [
            "https://github.com/Sparkz400/network-scope/releases/tag/v99.0.0",
            "gh attestation verify network-scope-99.0.0-linux-x86_64.tar.gz",
            "slsa-verifier verify-artifact",
            "sha256sum -c --ignore-missing SHA256SUMS",
        ] {
            assert!(text.contains(want), "{want}");
        }
        // The running version itself: up to date, and no verification text.
        let own = format!(r#"{{"tag_name":"v{}"}}"#, env!("CARGO_PKG_VERSION"));
        check_at(&opts, &serve(Box::leak(own.into_boxed_str()))).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("is up to date"), "{text}");
        assert!(!text.contains("slsa-verifier"));
        // A failure is an error (exit status 1), not a notice.
        let e = check_at(&opts, &serve("not json")).unwrap_err();
        assert!(e.starts_with("Update check failed:"), "{e}");
        // The command word needs its subcommand.
        assert_eq!(run(&args(&["update"])).unwrap_err(), "Use: update check");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
