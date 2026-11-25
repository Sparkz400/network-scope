// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Windows resources of both binaries (`network-scope` and `network-scope-cli`): the application
//! icon shown by Explorer, the taskbar and shortcuts, the version block of the file properties
//! and Task Manager, and the application manifest (assets/windows.manifest). Nothing is done
//! when the target is not Windows.
//!
//! The icon is rendered from SVG by assets/icon/build_icon.py and committed, so the build needs
//! only the resource compiler (rc.exe from the Windows SDK, which the MSVC toolchain installs).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon/network-scope.ico");
    println!("cargo:rerun-if-changed=assets/windows.manifest");
    // The build script runs on the host; the target decides whether the binaries are Windows ones.
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        windows_resources();
    }
}

#[cfg(windows)]
fn windows_resources() {
    let mut res = winresource::WindowsResource::new();
    // FILEVERSION and PRODUCTVERSION come from the package version (major.minor.patch.0).
    res.set_icon("assets/icon/network-scope.ico")
        .set_manifest_file("assets/windows.manifest")
        .set("ProductName", "Network Scope")
        .set("FileDescription", "Network Scope")
        .set("CompanyName", "Network Scope")
        .set("LegalCopyright", "MIT License")
        .set("Comments", env!("CARGO_PKG_HOMEPAGE"));
    if let Err(e) = res.compile() {
        // Without the resources the binaries still work, but a release must not lose its icon
        // and version block silently: fail the build.
        panic!("compiling the Windows resources failed (is the Windows SDK installed?): {e}");
    }
}
