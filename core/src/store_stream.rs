//! Writing a very large scan to the inventory in batches (ROADMAP B15).
//!
//! [`crate::store::save`] serialises a whole [`Snapshot`] into one row, which needs the whole
//! snapshot in memory. A scan of a /8 cannot work that way, so a [`ScanWriter`] takes the hosts
//! one at a time, keeps at most one batch of them in memory, and writes every batch in its own
//! transaction to the table `scan_hosts` (migration 5). The `scans` row is inserted when the
//! scan starts, marked incomplete, so a scan that is interrupted (or whose process dies) still
//! shows up as a partial scan with the hosts written so far; [`ScanWriter::finish`] sets the
//! final state.
//!
//! Readers do not notice the difference: [`crate::store::load`] and the other readers put the
//! hosts of `scan_hosts` back into the snapshot, in the order they were written.
use crate::{
    scan::{Host, Settings},
    sendlog::SentEntry,
    store::{self, Snapshot},
};
use rusqlite::{Connection, params};
use std::path::Path;

/// Hosts per transaction.
pub const BATCH_HOSTS: usize = 1000;

/// One scan being written. Memory use is one batch of serialised hosts, whatever the scan size.
pub struct ScanWriter {
    c: Connection,
    id: i64,
    base: Snapshot,
    pending: Vec<String>,
    seq: i64,
    batch: usize,
}

impl ScanWriter {
    /// Inserts the (incomplete, empty) scan and returns the writer.
    pub fn begin(path: &Path, targets: &str, settings: &Settings) -> Result<Self, String> {
        Self::begin_with(path, targets, settings, BATCH_HOSTS)
    }
    /// [`ScanWriter::begin`] with a batch size (at least 1), for tests.
    pub fn begin_with(
        path: &Path,
        targets: &str,
        settings: &Settings,
        batch: usize,
    ) -> Result<Self, String> {
        let c = store::open(path)?;
        let base = Snapshot {
            targets: targets.to_string(),
            complete: false,
            settings: settings.clone(),
            hosts: vec![],
            observations: vec![],
            notes: Default::default(),
            sent: vec![],
        };
        let data = serde_json::to_string(&base).map_err(|e| e.to_string())?;
        c.execute(
            "INSERT INTO scans(timestamp,targets,complete,hosts,snapshot) VALUES(?1,?2,0,0,?3)",
            params![store::now(), targets, data],
        )
        .map_err(|e| e.to_string())?;
        let id = c.last_insert_rowid();
        Ok(Self {
            c,
            id,
            base,
            pending: vec![],
            seq: 0,
            batch: batch.max(1),
        })
    }
    /// The scan id.
    pub fn id(&self) -> i64 {
        self.id
    }
    /// Hosts accepted so far (written or waiting for their batch).
    pub fn hosts(&self) -> usize {
        self.seq as usize + self.pending.len()
    }
    /// Takes one host; writes the batch when it is full.
    pub fn push(&mut self, host: &Host) -> Result<(), String> {
        self.pending
            .push(serde_json::to_string(host).map_err(|e| e.to_string())?);
        if self.pending.len() >= self.batch {
            self.flush()?;
        }
        Ok(())
    }
    /// Writes the waiting hosts in one transaction.
    pub fn flush(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let tx = self.c.transaction().map_err(|e| e.to_string())?;
        {
            let mut insert = tx
                .prepare_cached("INSERT INTO scan_hosts(scan_id,seq,host) VALUES(?1,?2,?3)")
                .map_err(|e| e.to_string())?;
            for (i, host) in self.pending.iter().enumerate() {
                insert
                    .execute(params![self.id, self.seq + i as i64, host])
                    .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        self.seq += self.pending.len() as i64;
        self.pending.clear();
        Ok(())
    }
    /// Writes the rest and records the final state; returns the scan id.
    pub fn finish(mut self, complete: bool, sent: Vec<SentEntry>) -> Result<i64, String> {
        self.flush()?;
        self.base.complete = complete;
        self.base.sent = sent;
        let data = serde_json::to_string(&self.base).map_err(|e| e.to_string())?;
        self.c
            .execute(
                "UPDATE scans SET complete=?1, hosts=?2, snapshot=?3 WHERE id=?4",
                params![complete, self.seq, data, self.id],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn host(n: u32) -> Host {
        Host {
            ip: std::net::Ipv4Addr::from(0x0a00_0000 + n).into(),
            responding: true,
            ping: Some(1),
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: vec![80],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: BTreeMap::new(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn db(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ns-writer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("x.sqlite")
    }

    #[test]
    fn hosts_are_written_in_batches_and_load_like_any_scan() {
        let path = db("batches");
        let mut w = ScanWriter::begin_with(&path, "10.0.0.0/8", &Settings::default(), 100).unwrap();
        for n in 0..250 {
            w.push(&host(n)).unwrap();
        }
        // Two full batches are committed (visible to another connection) while the rest waits.
        let rows = |p: &Path| -> i64 {
            store::open(p)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM scan_hosts", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(rows(&path), 200);
        assert_eq!(w.hosts(), 250);
        // Unfinished: the scan is on record as partial, with the hosts written so far.
        let partial = store::load(&path, w.id()).unwrap();
        assert!(!partial.complete);
        assert_eq!(partial.hosts.len(), 200);
        let id = w.finish(true, vec![]).unwrap();
        let s = store::load(&path, id).unwrap();
        assert!(s.complete && s.targets == "10.0.0.0/8");
        assert_eq!(s.hosts.len(), 250);
        assert!(
            s.hosts
                .iter()
                .enumerate()
                .all(|(i, h)| h.ip == host(i as u32).ip)
        );
        assert_eq!(store::list(&path).unwrap()[0].hosts, 250);
        assert_eq!(
            store::latest_complete(&path, "10.0.0.0/8", id + 1)
                .unwrap()
                .unwrap()
                .2
                .hosts
                .len(),
            250
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_ordinary_save_and_a_written_scan_are_the_same_snapshot() {
        let path = db("same");
        let hosts: Vec<Host> = (0..7).map(host).collect();
        let mut w = ScanWriter::begin(&path, "t", &Settings::default()).unwrap();
        for h in &hosts {
            w.push(h).unwrap();
        }
        let written = w.finish(true, vec![]).unwrap();
        let saved = store::save(
            &path,
            &Snapshot {
                targets: "t".into(),
                complete: true,
                settings: Settings::default(),
                hosts,
                observations: vec![],
                notes: Default::default(),
                sent: vec![],
            },
        )
        .unwrap();
        let a = serde_json::to_value(store::load(&path, written).unwrap()).unwrap();
        let b = serde_json::to_value(store::load(&path, saved).unwrap()).unwrap();
        assert_eq!(a, b);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_empty_scan_is_a_valid_complete_scan() {
        let path = db("empty");
        let w = ScanWriter::begin(&path, "t", &Settings::default()).unwrap();
        let id = w.finish(true, vec![]).unwrap();
        assert!(store::load(&path, id).unwrap().hosts.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
