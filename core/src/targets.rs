// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Helpers around the target list of a scan: reading it from a list file (`--targets-file`, the
//! desktop "Import address list…") and scanning it in random order (`--randomize`, the desktop
//! checkbox). The order only changes when each address is probed, never which addresses or
//! which probes; the scan engine is untouched.
use crate::scan::Targets;
use std::{net::IpAddr, path::Path};

/// The largest list file read.
pub const MAX_FILE_BYTES: u64 = 4 << 20;
/// The most addresses shuffled in memory (a /12); larger target sets must stay in order.
pub const MAX_RANDOMIZE: u64 = 1 << 20;

/// Target text from the contents of a list file: one entry per line or several separated by
/// spaces or commas; everything after `#` or `;` on a line is a comment, blank lines are
/// ignored. The result is one line of entries separated by spaces, ready for
/// [`crate::scan::parse_targets`].
pub fn from_list(contents: &str) -> String {
    contents
        .lines()
        .map(|line| line.split(['#', ';']).next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Reads a target list file (see [`from_list`]). An unreadable, oversized or empty file is an
/// error naming the file.
pub fn read_file(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{}: the list is larger than {} MiB",
            path.display(),
            MAX_FILE_BYTES >> 20
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = from_list(&String::from_utf8_lossy(&bytes));
    if text.is_empty() {
        return Err(format!("{}: the list has no addresses", path.display()));
    }
    Ok(text)
}

/// splitmix64: a small deterministic generator, plenty for ordering probes.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A number in `0..n` without modulo bias worth caring about for `n` far below 2^64.
    fn below(&mut self, n: usize) -> usize {
        ((u128::from(self.next()) * n as u128) >> 64) as usize
    }
}

/// Shuffles `hosts` in place (Fisher-Yates). The same seed gives the same order.
pub fn shuffle(hosts: &mut [IpAddr], seed: u64) {
    let mut rng = Rng(seed);
    for i in (1..hosts.len()).rev() {
        hosts.swap(i, rng.below(i + 1));
    }
}

/// A seed for a real run: the clock and the process id. Tests pass a fixed seed instead.
pub fn fresh_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    nanos ^ (u64::from(std::process::id()) << 32)
}

/// Every address of `targets` in random order. `Err` when there are more than
/// [`MAX_RANDOMIZE`] addresses (they would not fit in memory as a shuffled list).
pub fn randomized(targets: &Targets, seed: u64) -> Result<Vec<IpAddr>, String> {
    if targets.count() > MAX_RANDOMIZE {
        return Err(format!(
            "--randomize holds the addresses in memory: at most {MAX_RANDOMIZE} (a /12)"
        ));
    }
    let mut hosts: Vec<IpAddr> = targets.iter().collect();
    shuffle(&mut hosts, seed);
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{MAX_STREAM, parse_targets};

    fn hosts(n: u8) -> Vec<IpAddr> {
        (1..=n).map(|i| IpAddr::from([10, 0, 0, i])).collect()
    }

    #[test]
    fn list_files_allow_comments_blank_lines_and_mixed_separators() {
        let text = "# lab targets\n10.0.0.1\n\n  10.0.0.5-10.0.0.9   # the PLCs\n192.168.1.0/30, 10.9.9.9 ; trailing\n;whole line\n";
        assert_eq!(
            from_list(text),
            "10.0.0.1 10.0.0.5-10.0.0.9 192.168.1.0/30, 10.9.9.9"
        );
        assert_eq!(from_list("\n# only a comment\n"), "");
        // The result parses like typed text.
        let t = parse_targets(&from_list(text), true, MAX_STREAM).unwrap();
        assert!(t.count() >= 7);
        // Windows line endings.
        assert_eq!(from_list("10.0.0.1\r\n10.0.0.2\r\n"), "10.0.0.1 10.0.0.2");
    }

    #[test]
    fn a_list_file_is_read_and_bad_files_are_errors() {
        let dir = std::env::temp_dir().join(format!("ns-targets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("list.txt");
        std::fs::write(&good, "# hosts\n10.0.0.1\n10.0.0.2\n").unwrap();
        assert_eq!(read_file(&good).unwrap(), "10.0.0.1 10.0.0.2");
        let empty = dir.join("empty.txt");
        std::fs::write(&empty, "# nothing\n").unwrap();
        assert!(read_file(&empty).unwrap_err().contains("no addresses"));
        let e = read_file(&dir.join("missing.txt")).unwrap_err();
        assert!(e.contains("missing.txt"), "{e}");
        let big = dir.join("big.txt");
        std::fs::write(&big, vec![b'1'; (MAX_FILE_BYTES + 1) as usize]).unwrap();
        assert!(read_file(&big).unwrap_err().contains("larger than"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_same_seed_gives_the_same_order_and_another_seed_another() {
        let mut a = hosts(50);
        let mut b = hosts(50);
        let mut c = hosts(50);
        shuffle(&mut a, 7);
        shuffle(&mut b, 7);
        shuffle(&mut c, 8);
        assert_eq!(a, b, "deterministic for a seed");
        assert_ne!(a, c);
        assert_ne!(a, hosts(50), "it really moved");
    }

    #[test]
    fn a_shuffle_keeps_every_address_exactly_once() {
        for n in [0u8, 1, 2, 3, 200] {
            let original = hosts(n);
            let mut shuffled = original.clone();
            shuffle(&mut shuffled, 42);
            let mut sorted = shuffled.clone();
            sorted.sort();
            assert_eq!(sorted, original, "n = {n}");
        }
    }

    #[test]
    fn the_shuffle_is_not_biased_toward_the_front() {
        // Over many seeds, the first address of 10 lands in every slot roughly equally often.
        let mut slots = [0u32; 10];
        for seed in 0..5000u64 {
            let mut v = hosts(10);
            shuffle(&mut v, seed);
            slots[v.iter().position(|h| *h == hosts(1)[0]).unwrap()] += 1;
        }
        for (slot, count) in slots.iter().enumerate() {
            assert!((350..=650).contains(count), "slot {slot}: {count}");
        }
    }

    #[test]
    fn randomized_covers_the_targets_and_refuses_huge_sets() {
        let t = parse_targets("10.0.0.0/28", true, MAX_STREAM).unwrap();
        let shuffled = randomized(&t, 1).unwrap();
        let mut sorted = shuffled.clone();
        sorted.sort();
        assert_eq!(sorted, t.iter().collect::<Vec<_>>());
        assert_eq!(shuffled, randomized(&t, 1).unwrap());
        let huge = parse_targets("10.0.0.0/8", true, MAX_STREAM).unwrap();
        assert!(randomized(&huge, 1).unwrap_err().contains("at most"));
    }
}
