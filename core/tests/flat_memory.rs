//! Memory stays flat for a /8 (ROADMAP B15): the target generator, the planner behind
//! `--dry-run` and the scope check handle 10.0.0.0/8 (16,777,214 addresses) without ever holding
//! the addresses. A counting global allocator measures the peak number of live bytes; this file
//! is its own test binary with a single test, so nothing else allocates concurrently.
use network_scope_core::{
    plan,
    scan::{self, Settings},
    scope,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call to the system allocator and only counts the bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                let live = LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed)
                    + (new_size - layout.size());
                PEAK.fetch_max(live, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Peak live bytes above the level when `f` started.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(base))
}

#[test]
fn a_slash_8_streams_through_the_generator_the_planner_and_the_scope_check() {
    // 16.7 million addresses would take 64 MiB as a bare `Vec<u32>` and about 400 MB as a
    // `Vec<IpAddr>`; the budget is far below even the smaller of them.
    const BUDGET: usize = 1 << 20;
    let targets = scan::parse_targets("10.0.0.0/8", true, scan::MAX_STREAM).unwrap();
    let expected = (1u64 << 24) - 2;
    assert_eq!(targets.count(), expected);

    // The generator: walk every address.
    let (seen, peak) = peak_during(|| {
        targets
            .iter()
            .map(|ip| u64::from(ip.is_ipv4()))
            .sum::<u64>()
    });
    assert_eq!(seen, expected);
    assert!(peak < BUDGET, "target generator peaked at {peak} bytes");

    // The planner behind `scan --dry-run`: a group per address family, never a host list.
    let settings = Settings::default();
    let ports = scan::parse_ports("80,443,502").unwrap();
    let (groups, peak) = peak_during(|| plan::scan(targets.iter(), &ports, &settings, None));
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].hosts, expected);
    assert!(peak < BUDGET, "planner peaked at {peak} bytes");

    // The scope guard judges the ranges, not the addresses.
    let declared = scope::Scope::parse("10.0.0.0/8").unwrap();
    let (verdict, peak) = peak_during(|| scope::assess(&targets, Some(&declared)));
    assert_eq!((verdict.public, verdict.out_of_scope), (0, 0));
    assert_eq!(verdict.total, expected);
    assert!(peak < BUDGET, "scope check peaked at {peak} bytes");
}
