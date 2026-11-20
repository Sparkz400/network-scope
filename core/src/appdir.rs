//! The per-user configuration folder that holds `cves.json`, `probes.json`, `scope.txt` and the
//! feed caches: `%LOCALAPPDATA%/NetworkScope` on Windows, else `$XDG_CONFIG_HOME/NetworkScope`,
//! else `~/.config/NetworkScope` (most Linux desktops and macOS do not set `XDG_CONFIG_HOME`).
use std::path::{Path, PathBuf};

/// `NetworkScope/<file>` in the per-user configuration folder; `None` only when no folder is
/// known at all (no `LOCALAPPDATA`, `XDG_CONFIG_HOME` or `HOME`).
pub fn file(name: &str) -> Option<PathBuf> {
    folder(
        std::env::var_os("LOCALAPPDATA"),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
    .map(|dir| dir.join(name))
}

fn folder(
    local_app_data: Option<std::ffi::OsString>,
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let non_empty = |v: Option<std::ffi::OsString>| v.filter(|v| !v.is_empty());
    non_empty(local_app_data)
        .or_else(|| non_empty(xdg_config_home))
        .map(PathBuf::from)
        .or_else(|| non_empty(home).map(|h| Path::new(&h).join(".config")))
        .map(|base| base.join("NetworkScope"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_app_data_then_xdg_then_home_config() {
        let s = |v: &str| Some(std::ffi::OsString::from(v));
        assert_eq!(
            folder(s("L"), s("X"), s("H")),
            Some(Path::new("L").join("NetworkScope"))
        );
        assert_eq!(
            folder(None, s("X"), s("H")),
            Some(Path::new("X").join("NetworkScope"))
        );
        assert_eq!(
            folder(s(""), None, s("H")),
            Some(Path::new("H").join(".config").join("NetworkScope"))
        );
        assert_eq!(folder(None, None, None), None);
    }
}
