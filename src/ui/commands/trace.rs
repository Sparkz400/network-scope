//! `trace TARGET [--max-hops 20] [--timeout 1000] [--fast --trace-method udp|tcp --trace-port N]`.
use crate::ui::{
    Ctx,
    args::{number, scan_settings, trace_method, trace_port},
    guard, output,
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, pos) = (ctx.opts.clone(), ctx.pos.clone());
    let (opts, pos) = (&opts, &pos);
    let target: std::net::IpAddr = pos
        .first()
        .ok_or("Provide a target IP address")?
        .parse()
        .map_err(|_| "Target must be an IP address".to_string())?;
    // The same scope rule as `scan` (ROADMAP H54).
    if !guard::enforce(ctx, &[target][..])? {
        return Ok(());
    }
    let hops: u8 = number(opts, "max-hops", 20)?;
    let timeout: u32 = number(opts, "timeout", 1000)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(128)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let blocking = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
    let method = match opts.get("trace-method") {
        Some(m) => trace_method(m)?,
        None => crate::trace::TraceMethod::Icmp,
    };
    // TCP/UDP traceroute transmits beyond ICMP echo: like in scans, only with --fast.
    if method != crate::trace::TraceMethod::Icmp && !opts.contains_key("fast") {
        return Err("TCP/UDP traceroute needs --fast (Safe Mode allows ICMP only)".into());
    }
    let rate: u32 = number(opts, "rate", 0)?;
    let gate = if rate > 0 {
        crate::core::Gate::per_second(f64::from(rate), (f64::from(rate) / 10.0).max(1.0))
    } else {
        crate::core::Gate::unlimited()
    };
    let v4 = || match target {
        std::net::IpAddr::V4(v4) => Ok(v4),
        _ => Err("TCP/UDP traceroute is IPv4 only".to_string()),
    };
    let path = match method {
        crate::trace::TraceMethod::Icmp => {
            runtime.block_on(crate::trace::trace(target, hops, timeout, &blocking, &gate))?
        }
        crate::trace::TraceMethod::Udp => runtime.block_on(crate::trace::trace_udp(
            v4()?,
            hops,
            timeout,
            &blocking,
            &gate,
        ))?,
        crate::trace::TraceMethod::Tcp => {
            let port = trace_port(
                opts.get("trace-port")
                    .ok_or("TCP traceroute needs --trace-port N (an open port)")?,
            )?;
            let settings = scan_settings(opts)?;
            crate::trace::assemble(crate::syn::tcp_trace(
                &settings,
                v4()?,
                port,
                hops,
                timeout,
                &gate,
            )?)
        }
    };
    let mut text = format!("Path to {target}\n");
    for h in &path {
        text.push_str(&format!(
            "{:>3}  {:<40} {}\n",
            h.ttl,
            h.ip.map_or("*".to_string(), |ip| ip.to_string()),
            h.rtt.map_or(String::new(), |r| format!("{r} ms"))
        ));
    }
    output(text.trim_end(), opts)
}

#[cfg(test)]
mod tests {
    use crate::ui::{run, testutil::args};

    #[test]
    fn tcp_and_udp_traceroute_need_fast() {
        assert!(
            run(&args(&["trace", "127.0.0.1", "--trace-method", "udp"]))
                .unwrap_err()
                .contains("--fast")
        );
    }
}
