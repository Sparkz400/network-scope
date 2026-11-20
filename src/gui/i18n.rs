//! A minimal translation layer for the desktop app: no crates, no code generation.
//!
//! Text in the code is English and is wrapped in [`tr!`]. The macro looks the English text up in
//! the catalog of the chosen language and falls back to the English text itself when there is no
//! entry, so a missing translation shows English and never breaks anything. The German catalog is
//! the plain data file `lang/de.txt` (embedded at build time), one entry per line:
//!
//! ```text
//! # comment
//! English text || Deutscher Text
//! {} responding · {} with open ports || {} antworten · {} mit offenen Ports
//! ```
//!
//! Placeholders are `{}` (filled in order) or `{1}`, `{2}`, ... (a number picks an argument, so a
//! translation may reorder them). `tr!("text")` gives a `&'static str`; `tr!("text {}", value)`
//! gives a `String`. The language is chosen in Settings (Automatic, English, Deutsch); Automatic
//! follows the operating system's locale ([`detect`]).
use std::{collections::HashMap, fmt::Display, sync::OnceLock};

/// The text of a message in the current language: `tr!("Start")` or `tr!("{} hosts", n)`.
macro_rules! tr {
    ($text:literal) => {
        $crate::gui::i18n::text($text)
    };
    ($text:literal, $($arg:expr),+ $(,)?) => {
        $crate::gui::i18n::text_fmt($text, &[$(&$arg as &dyn ::std::fmt::Display),+])
    };
}
pub(crate) use tr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    English,
    German,
}

impl Lang {
    /// The code stored in the preferences.
    pub fn code(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::German => "de",
        }
    }
    /// The name of the language in that language (the picker shows it as is).
    pub fn name(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::German => "Deutsch",
        }
    }
    /// `en` or `de` (also `de-DE`, `de_AT.UTF-8`, `German`); anything else is `None`.
    pub fn from_locale(text: &str) -> Option<Self> {
        let t = text.trim().to_ascii_lowercase();
        let primary = t.split(['-', '_', '.', '@', ':']).next().unwrap_or("");
        match primary {
            "de" | "german" | "deutsch" => Some(Self::German),
            "en" | "english" | "c" | "posix" => Some(Self::English),
            _ => None,
        }
    }
    /// The language for a preference value: `auto` (or empty) follows the system, `en` / `de`
    /// force one, an unknown value is treated as `auto`.
    pub fn resolve(preference: &str, system: Option<&str>) -> Self {
        match preference.trim() {
            "" | "auto" => system.and_then(Self::from_locale).unwrap_or(Self::English),
            other => Self::from_locale(other)
                .or_else(|| system.and_then(Self::from_locale))
                .unwrap_or(Self::English),
        }
    }
}

/// Every language the picker offers.
pub const LANGUAGES: [Lang; 2] = [Lang::English, Lang::German];

thread_local! {
    /// The language of this thread. The window runs on one thread, and a test that switches the
    /// language does not disturb the tests running beside it.
    static CURRENT: std::cell::Cell<Lang> = const { std::cell::Cell::new(Lang::English) };
}

pub fn set(lang: Lang) {
    CURRENT.with(|c| c.set(lang));
}
pub fn current() -> Lang {
    CURRENT.with(std::cell::Cell::get)
}

const GERMAN: &str = include_str!("lang/de.txt");

/// Blank lines and comments (`# ...`) are not entries; a text that starts with `#` directly
/// (`#{} hosts`) is an entry.
fn is_skipped(line: &str) -> bool {
    line.trim().is_empty() || line == "#" || line.starts_with("# ")
}

/// Parses a catalog: `source || translation` lines; blank lines and `#` comments are skipped.
pub fn parse_catalog(text: &'static str) -> HashMap<&'static str, &'static str> {
    text.lines()
        .filter(|l| !is_skipped(l))
        .filter_map(|l| l.split_once(" || "))
        .map(|(en, tr)| (en.trim(), tr.trim()))
        .collect()
}

fn german() -> &'static HashMap<&'static str, &'static str> {
    static CATALOG: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    CATALOG.get_or_init(|| parse_catalog(GERMAN))
}

/// The catalog of a language (`None` for English: the source text is the English text).
pub fn catalog(lang: Lang) -> Option<&'static HashMap<&'static str, &'static str>> {
    match lang {
        Lang::English => None,
        Lang::German => Some(german()),
    }
}

/// The translation of `text` in `lang`, or `text` itself when there is none.
pub fn translate(lang: Lang, text: &'static str) -> &'static str {
    catalog(lang)
        .and_then(|c| c.get(text).copied())
        .unwrap_or(text)
}

/// The translation of `text` in the current language (the macro form is [`tr!`]).
pub fn text(text: &'static str) -> &'static str {
    translate(current(), text)
}

/// Fills `{}` and `{N}` placeholders of `template` with `args`. A placeholder without an
/// argument stays as written.
pub fn fill(template: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut next = 0;
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        let index = if name.is_empty() {
            next += 1;
            Some(next - 1)
        } else {
            name.parse::<usize>().ok().and_then(|n| n.checked_sub(1))
        };
        match index.and_then(|i| args.get(i)) {
            Some(arg) => out.push_str(&arg.to_string()),
            None => out.push_str(&rest[open..open + close + 2]),
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The translation of a template, with its placeholders filled in (the macro form is [`tr!`]).
pub fn text_fmt(template: &'static str, args: &[&dyn Display]) -> String {
    fill(text(template), args)
}

/// The language of the operating system as a locale text (`de_DE.UTF-8`, `de-DE`, ...), if it
/// can be read.
pub fn system_locale() -> Option<String> {
    // NETWORK_SCOPE_LANG (en, de) overrides the system, e.g. for screenshots and tests.
    if let Ok(v) = std::env::var("NETWORK_SCOPE_LANG")
        && !v.is_empty()
    {
        return Some(v);
    }
    for var in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
            && v != "C"
            && v != "POSIX"
        {
            return Some(v);
        }
    }
    platform_locale()
}

#[cfg(windows)]
fn platform_locale() -> Option<String> {
    unsafe extern "system" {
        fn GetUserDefaultLocaleName(name: *mut u16, len: i32) -> i32;
    }
    let mut buffer = [0u16; 85];
    // SAFETY: the buffer is LOCALE_NAME_MAX_LENGTH (85) wide, as the function requires.
    let n = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), buffer.len() as i32) };
    (n > 1).then(|| String::from_utf16_lossy(&buffer[..(n as usize - 1)]))
}
#[cfg(target_os = "macos")]
fn platform_locale() -> Option<String> {
    let out = std::process::Command::new("defaults")
        .args(["read", "-g", "AppleLocale"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}
#[cfg(not(any(windows, target_os = "macos")))]
fn platform_locale() -> Option<String> {
    None
}

/// The language the preference value `preference` selects on this system.
pub fn detect(preference: &str) -> Lang {
    Lang::resolve(preference, system_locale().as_deref())
}

/// The string literals inside `tr!(...)` calls of a source text, unescaped. Used by the test that
/// keeps the catalog complete.
#[cfg(test)]
pub fn literals(source: &str) -> Vec<String> {
    let mut found = vec![];
    let mut rest = source;
    while let Some(at) = rest.find("tr!(") {
        // `str!(`, `attr!(` and the like are not ours.
        let before = rest[..at].chars().next_back();
        rest = &rest[at + 4..];
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let trimmed = rest.trim_start();
        let Some(body) = trimmed.strip_prefix('"') else {
            continue;
        };
        let mut text = String::new();
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => text.push('\n'),
                    Some('"') => text.push('"'),
                    Some('\\') => text.push('\\'),
                    Some('\n') => {
                        // A line continuation swallows the next line's indentation.
                        let remaining = chars.as_str();
                        let skip = remaining.len() - remaining.trim_start().len();
                        chars = remaining[skip..].chars();
                    }
                    Some(other) => {
                        text.push('\\');
                        text.push(other);
                    }
                    None => break,
                },
                c => text.push(c),
            }
        }
        found.push(text);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_translates_and_falls_back_to_the_source_text() {
        assert_eq!(translate(Lang::English, "Start scan"), "Start scan");
        assert_eq!(translate(Lang::German, "Start scan"), "Scan starten");
        // A text without an entry stays English.
        assert_eq!(
            translate(Lang::German, "No such message in the catalog"),
            "No such message in the catalog"
        );
    }

    #[test]
    fn placeholders_are_filled_in_order_or_by_number() {
        assert_eq!(fill("{} of {}", &[&3, &"x"]), "3 of x");
        assert_eq!(fill("{2} before {1}", &[&"a", &"b"]), "b before a");
        // A missing argument and a stray brace stay as written.
        assert_eq!(fill("{} and {}", &[&1]), "1 and {}");
        assert_eq!(fill("open { brace", &[]), "open { brace");
        assert_eq!(fill("{0}", &[&1]), "{0}");
        assert_eq!(fill("no placeholders", &[&1]), "no placeholders");
        assert_eq!(fill("ünï {} ✓", &[&"→"]), "ünï → ✓");
    }

    #[test]
    fn the_macro_translates_with_the_current_language() {
        // The language belongs to this thread; the test restores it anyway.
        set(Lang::German);
        assert_eq!(tr!("Start scan"), "Scan starten");
        assert_eq!(
            tr!("{} responding · {} with open ports", 4, 2),
            "4 antworten · 2 mit offenen Ports"
        );
        set(Lang::English);
        assert_eq!(tr!("Start scan"), "Start scan");
        assert_eq!(
            tr!("{} responding · {} with open ports", 4, 2),
            "4 responding · 2 with open ports"
        );
    }

    #[test]
    fn locales_and_preferences_resolve_to_a_language() {
        for (locale, lang) in [
            ("de", Some(Lang::German)),
            ("de-DE", Some(Lang::German)),
            ("de_AT.UTF-8", Some(Lang::German)),
            ("DE_CH", Some(Lang::German)),
            ("en_US.UTF-8", Some(Lang::English)),
            ("C", Some(Lang::English)),
            ("fr_FR", None),
            ("", None),
        ] {
            assert_eq!(Lang::from_locale(locale), lang, "{locale}");
        }
        // Automatic follows the system and falls back to English.
        assert_eq!(Lang::resolve("auto", Some("de_DE.UTF-8")), Lang::German);
        assert_eq!(Lang::resolve("", Some("de-DE")), Lang::German);
        assert_eq!(Lang::resolve("auto", Some("fr_FR")), Lang::English);
        assert_eq!(Lang::resolve("auto", None), Lang::English);
        // An explicit choice wins over the system; an unknown one counts as automatic.
        assert_eq!(Lang::resolve("en", Some("de_DE")), Lang::English);
        assert_eq!(Lang::resolve("de", Some("en_US")), Lang::German);
        assert_eq!(Lang::resolve("klingon", Some("de_DE")), Lang::German);
        for l in LANGUAGES {
            assert_eq!(Lang::from_locale(l.code()), Some(l));
        }
    }

    #[test]
    fn the_catalog_has_no_duplicates_and_matching_placeholders() {
        let mut seen = std::collections::HashSet::new();
        let mut entries = 0;
        for line in GERMAN.lines().filter(|l| !is_skipped(l)) {
            let (en, de) = line
                .split_once(" || ")
                .unwrap_or_else(|| panic!("not 'English || Deutsch': {line}"));
            let (en, de) = (en.trim(), de.trim());
            assert!(!de.is_empty(), "empty translation: {en}");
            assert!(seen.insert(en), "duplicate entry: {en}");
            assert!(!de.contains(" || "), "stray separator: {line}");
            // Same number of arguments on both sides.
            let count = |s: &str| {
                let sequential = s.matches("{}").count();
                let numbered = (1..=9).filter(|n| s.contains(&format!("{{{n}}}"))).count();
                sequential.max(numbered)
            };
            assert_eq!(count(en), count(de), "placeholders differ: {line}");
            entries += 1;
        }
        assert!(entries > 100, "catalog too small: {entries}");
        assert_eq!(parse_catalog(GERMAN).len(), entries);
    }

    #[test]
    fn every_text_wrapped_in_the_macro_has_a_german_entry() {
        let sources = [
            include_str!("mod.rs"),
            include_str!("controls.rs"),
            include_str!("windows.rs"),
            include_str!("settings.rs"),
            include_str!("details.rs"),
            include_str!("home.rs"),
            include_str!("quick.rs"),
            include_str!("map.rs"),
            include_str!("convenience.rs"),
            include_str!("palette.rs"),
            include_str!("tables.rs"),
            include_str!("updates.rs"),
            include_str!("preset_ui.rs"),
            include_str!("scheduler.rs"),
            include_str!("ot.rs"),
            include_str!("timeline.rs"),
        ];
        let catalog = parse_catalog(GERMAN);
        let mut missing = vec![];
        let mut total = 0;
        for source in sources {
            // The tests of a file are not part of the interface.
            let code = source.split("#[cfg(test)]").next().unwrap_or(source);
            for text in literals(code) {
                total += 1;
                if !catalog.contains_key(text.as_str()) {
                    missing.push(text);
                }
            }
        }
        assert!(total > 100, "only {total} translated texts found");
        assert!(
            missing.is_empty(),
            "no German entry for:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn the_literal_scanner_unescapes_and_skips_look_alikes() {
        let src = r#"a(tr!("One")); b(tr!("Two \"quoted\" and {}", x)); c(str!("no")); d(tr!(
            "Three"
        )); e(tr!(variable)); f(tr!("a \
             b"));"#;
        assert_eq!(
            literals(src),
            ["One", "Two \"quoted\" and {}", "Three", "a b"]
        );
    }
}
