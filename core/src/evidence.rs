//! The reasons behind a conclusion, with a confidence score (ROADMAP A9: explain every
//! conclusion). Device types, OS guesses and findings each carry an [`Evidence`]; the CLI host
//! details, the reports, the JSON exports and the GUI show it.
//!
//! The scores are heuristic. They say how much independent evidence backs a conclusion and how
//! far ahead of the runner-up it is, not a calibrated probability: 90 and above is a direct
//! observation (a banner, a protocol answer), 70 is several matching hints, 40 and below is a
//! version-based hint or a single weak signal.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Why a device type, OS guess or finding was concluded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What was observed, one short phrase each ("port 9100", "PJL banner", "HP MAC prefix").
    pub reasons: Vec<String>,
    /// 0 to 100; 0 means "not scored" (data from before scores existed).
    pub confidence: u8,
}

/// Reasons are joined with this in the identity map (`os.evidence`, `device.evidence`).
const SEPARATOR: &str = "; ";

impl Evidence {
    /// `confidence` is clamped to 100; empty and duplicate reasons are dropped.
    pub fn new<I, S>(reasons: I, confidence: u8) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut out: Vec<String> = vec![];
        for r in reasons {
            let r = r.into();
            if !r.trim().is_empty() && !out.contains(&r) {
                out.push(r);
            }
        }
        Self {
            reasons: out,
            confidence: confidence.min(100),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty() && self.confidence == 0
    }

    /// "port 9100; PJL banner; HP MAC prefix".
    pub fn because(&self) -> String {
        self.reasons.join(SEPARATOR)
    }

    /// One line for tooltips and host details: "printer (75 %) because port 9100; PJL banner".
    pub fn line(&self, conclusion: &str) -> String {
        let mut s = conclusion.to_string();
        if self.confidence > 0 {
            s.push_str(&format!(" ({} %)", self.confidence));
        }
        if !self.reasons.is_empty() {
            s.push_str(" because ");
            s.push_str(&self.because());
        }
        s
    }

    /// Reads `<prefix>.evidence` and `<prefix>.confidence` (`"70%"` or `"70"`) from a host's
    /// identity map; `prefix` is `os` or `device`. `None` when neither is present.
    pub fn from_identity(identity: &BTreeMap<String, String>, prefix: &str) -> Option<Self> {
        let reasons = identity
            .get(&format!("{prefix}.evidence"))
            .map(String::as_str)
            .unwrap_or("");
        let confidence = identity
            .get(&format!("{prefix}.confidence"))
            .and_then(|c| c.trim().trim_end_matches('%').trim().parse::<u8>().ok())
            .unwrap_or(0);
        let e = Self::new(reasons.split(SEPARATOR), confidence);
        (!e.is_empty()).then_some(e)
    }

    /// Writes `<prefix>.evidence` and `<prefix>.confidence` ("70%") into an identity map.
    pub fn store(&self, identity: &mut BTreeMap<String, String>, prefix: &str) {
        identity.insert(format!("{prefix}.evidence"), self.because());
        identity.insert(
            format!("{prefix}.confidence"),
            format!("{}%", self.confidence),
        );
    }
}

/// Confidence from a score and the runner-up's score: the evidence for the winner, plus half
/// of its lead, clamped to 10..=95 (an inferred conclusion is never certain).
pub fn confidence_from_scores(score: i32, runner_up: i32) -> u8 {
    let margin = (score - runner_up).max(0);
    (score.min(70) + margin.min(30) / 2).clamp(10, 95) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_clamps_and_drops_empty_and_duplicate_reasons() {
        let e = Evidence::new(["port 9100", " ", "port 9100", "PJL banner"], 250);
        assert_eq!(e.reasons, ["port 9100", "PJL banner"]);
        assert_eq!(e.confidence, 100);
        assert_eq!(e.because(), "port 9100; PJL banner");
        assert_eq!(
            Evidence::new(["port 9100"], 75).line("Printer"),
            "Printer (75 %) because port 9100"
        );
        assert_eq!(Evidence::default().line("x"), "x");
        assert!(Evidence::default().is_empty());
    }

    #[test]
    fn identity_round_trip_and_absence() {
        let mut id = BTreeMap::new();
        assert_eq!(Evidence::from_identity(&id, "os"), None);
        let e = Evidence::new(["initial TTL 64", "TCP options M,S,T,N,W"], 70);
        e.store(&mut id, "os");
        assert_eq!(id["os.confidence"], "70%");
        assert_eq!(Evidence::from_identity(&id, "os"), Some(e));
        // A confidence alone (an imported Nmap result) still counts; junk does not.
        let mut nmap = BTreeMap::new();
        nmap.insert("os.confidence".to_string(), "93%".to_string());
        assert_eq!(Evidence::from_identity(&nmap, "os").unwrap().confidence, 93);
        nmap.insert("os.confidence".to_string(), "lots".to_string());
        assert_eq!(Evidence::from_identity(&nmap, "os"), None);
        // Not scored data from an older export keeps working.
        let old: Evidence = serde_json::from_str(r#"{"reasons":["a"],"confidence":0}"#).unwrap();
        assert_eq!(old.reasons, ["a"]);
    }

    #[test]
    fn confidence_grows_with_evidence_and_lead() {
        assert_eq!(confidence_from_scores(35, 0), 50);
        assert_eq!(confidence_from_scores(35, 35), 35);
        assert_eq!(confidence_from_scores(200, 0), 85);
        assert_eq!(confidence_from_scores(30, 30), 30);
        assert!(confidence_from_scores(5, 5) >= 10);
        assert!(confidence_from_scores(500, 0) <= 95);
    }
}
