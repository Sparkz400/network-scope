//! Runtime-loaded capture driver: the portable binary has no Npcap link dependency.
use libloading::Library;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
type Handle = *mut c_void;
#[repr(C)]
struct Header {
    seconds: std::os::raw::c_long,
    micros: std::os::raw::c_long,
    caplen: u32,
    len: u32,
}
#[repr(C)]
struct Device {
    next: *mut Device,
    name: *const c_char,
    description: *const c_char,
    addresses: *mut c_void,
    flags: u32,
}
/// `struct bpf_program` from pcap/bpf.h.
#[repr(C)]
struct BpfProgram {
    len: c_uint,
    insns: *mut c_void,
}
/// `PCAP_NETMASK_UNKNOWN`: the filter does not use broadcast tests, so no netmask is needed.
const NETMASK_UNKNOWN: u32 = 0xffff_ffff;
type ErrorBuffer = [c_char; 256];
type OpenFn = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> Handle;
type NextFn = unsafe extern "C" fn(Handle, *mut *const Header, *mut *const u8) -> c_int;
type SendFn = unsafe extern "C" fn(Handle, *const u8, c_int) -> c_int;
type CloseFn = unsafe extern "C" fn(Handle);
type DatalinkFn = unsafe extern "C" fn(Handle) -> c_int;
type NonblockFn = unsafe extern "C" fn(Handle, c_int, *mut c_char) -> c_int;
type CompileFn = unsafe extern "C" fn(Handle, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type SetFilterFn = unsafe extern "C" fn(Handle, *mut BpfProgram) -> c_int;
type FreeCodeFn = unsafe extern "C" fn(*mut BpfProgram);
type GetErrFn = unsafe extern "C" fn(Handle) -> *const c_char;

/// Entry points resolved once when the handle is opened; the hot paths
/// (`next`, `send`) no longer look symbols up per call.
struct Api {
    next: NextFn,
    send: SendFn,
    close: CloseFn,
}
pub struct Capture {
    api: Api,
    handle: Handle,
    /// `pcap_datalink`: 1 Ethernet, 0 BSD loopback (only accepted by [`PassiveCapture::open_wire`]).
    link: c_int,
    // Keeps the function pointers in `api` valid; dropped after `Drop::drop` closed the handle.
    _lib: Library,
}
/// Library names tried in order. macOS ships `libpcap.A.dylib` (with a `libpcap.dylib`
/// symlink); Linux distributions ship `libpcap.so.1`, some only `libpcap.so.0.8`.
#[cfg_attr(windows, allow(dead_code))]
pub fn library_candidates(macos: bool) -> &'static [&'static str] {
    if macos {
        &[
            "libpcap.A.dylib",
            "libpcap.dylib",
            "/usr/lib/libpcap.A.dylib",
            "/usr/lib/libpcap.dylib",
        ]
    } else {
        &["libpcap.so.1", "libpcap.so", "libpcap.so.0.8"]
    }
}
/// `%SystemRoot%\System32\Npcap\wpcap.dll`, built from separate components so the path
/// only contains backslashes on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
fn npcap_dll_path(system_root: Option<std::ffi::OsString>) -> std::path::PathBuf {
    std::path::PathBuf::from(system_root.unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join("Npcap")
        .join("wpcap.dll")
}
fn library() -> Result<Library, String> {
    #[cfg(windows)]
    {
        // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR (0x100) needs a fully qualified path with
        // backslashes: "System32/Npcap/wpcap.dll" (forward slashes) is rejected and the
        // installed driver looked missing. `npcap_dll_path` joins the components separately.
        let path = npcap_dll_path(std::env::var_os("SystemRoot"));
        let loaded = unsafe {
            libloading::os::windows::Library::load_with_flags(path, 0x100 | 0x1000)
                .map(Library::from)
        };
        loaded.map_err(|e| format!("Capture driver unavailable (install Npcap on Windows): {e}"))
    }
    #[cfg(not(windows))]
    {
        let mut errors = vec![];
        for name in library_candidates(cfg!(target_os = "macos")) {
            match unsafe { Library::new(*name) } {
                Ok(lib) => return Ok(lib),
                Err(e) => errors.push(format!("{name}: {e}")),
            }
        }
        Err(format!(
            "Capture driver unavailable (install libpcap): {}",
            errors.join("; ")
        ))
    }
}
fn error_text(error: &ErrorBuffer) -> String {
    // libpcap writes a NUL-terminated message; fall back to the whole buffer if it did not.
    let bytes: Vec<u8> = error
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| c.to_ne_bytes()[0])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
pub fn interfaces() -> Result<Vec<(String, String)>, String> {
    unsafe {
        let lib = library()?;
        let find = lib
            .get::<unsafe extern "C" fn(*mut *mut Device, *mut c_char) -> c_int>(
                b"pcap_findalldevs\0",
            )
            .map_err(|e| e.to_string())?;
        let free = lib
            .get::<unsafe extern "C" fn(*mut Device)>(b"pcap_freealldevs\0")
            .map_err(|e| e.to_string())?;
        let mut first = std::ptr::null_mut();
        let mut error: ErrorBuffer = [0; 256];
        if find(&mut first, error.as_mut_ptr()) != 0 {
            return Err(error_text(&error));
        }
        let mut current = first;
        let mut result = vec![];
        while !current.is_null() {
            let d = &*current;
            if !d.name.is_null() {
                result.push((
                    CStr::from_ptr(d.name).to_string_lossy().into_owned(),
                    if d.description.is_null() {
                        String::new()
                    } else {
                        CStr::from_ptr(d.description).to_string_lossy().into_owned()
                    },
                ));
            }
            current = d.next;
        }
        free(first);
        Ok(result)
    }
}
/// Kernel filter for the SYN engine: only TCP addressed to our source IPv4, or to one of the
/// interface's IPv6 source addresses (`v6`), reaches user space. The engine resolves MACs
/// through the OS, so it needs no ARP or NDP frames.
pub fn syn_filter(source: std::net::Ipv4Addr, v6: &[std::net::Ipv6Addr]) -> String {
    if v6.is_empty() {
        return format!("tcp and dst host {source}");
    }
    let hosts: Vec<String> = std::iter::once(source.to_string())
        .chain(v6.iter().map(ToString::to_string))
        .map(|host| format!("dst host {host}"))
        .collect();
    format!("tcp and ({})", hosts.join(" or "))
}
impl Capture {
    /// Promiscuous capture without a kernel filter (passive discovery and DCP).
    pub fn open(name: &str) -> Result<Self, String> {
        Self::open_with(name, true, None)
    }
    /// Opens an Ethernet capture. `filter` is compiled into a kernel BPF program so
    /// unrelated traffic never reaches user space.
    pub fn open_with(name: &str, promiscuous: bool, filter: Option<&str>) -> Result<Self, String> {
        Self::open_link(name, promiscuous, filter, false)
    }
    /// [`Capture::open_with`]; `loopback` also accepts the BSD loopback link type (Npcap's
    /// loopback adapter, `lo0`), which has no Ethernet header.
    fn open_link(
        name: &str,
        promiscuous: bool,
        filter: Option<&str>,
        loopback: bool,
    ) -> Result<Self, String> {
        if name.is_empty() {
            return Err("Select a capture interface first.".into());
        }
        let filter = filter
            .map(CString::new)
            .transpose()
            .map_err(|e| e.to_string())?;
        let name = CString::new(name).map_err(|e| e.to_string())?;
        unsafe {
            let lib = library()?;
            macro_rules! sym {
                ($ty:ty, $name:literal) => {
                    *lib.get::<$ty>($name)
                        .map_err(|e| format!("{}: {e}", String::from_utf8_lossy($name)))?
                };
            }
            let open: OpenFn = sym!(OpenFn, b"pcap_open_live\0");
            let api = Api {
                next: sym!(NextFn, b"pcap_next_ex\0"),
                send: sym!(SendFn, b"pcap_sendpacket\0"),
                close: sym!(CloseFn, b"pcap_close\0"),
            };
            let datalink: DatalinkFn = sym!(DatalinkFn, b"pcap_datalink\0");
            let nonblock: NonblockFn = sym!(NonblockFn, b"pcap_setnonblock\0");
            let compile: CompileFn = sym!(CompileFn, b"pcap_compile\0");
            let set_filter: SetFilterFn = sym!(SetFilterFn, b"pcap_setfilter\0");
            let free_code: FreeCodeFn = sym!(FreeCodeFn, b"pcap_freecode\0");
            let get_err: GetErrFn = sym!(GetErrFn, b"pcap_geterr\0");
            let mut error: ErrorBuffer = [0; 256];
            let handle = open(
                name.as_ptr(),
                65536,
                c_int::from(promiscuous),
                50,
                error.as_mut_ptr(),
            );
            if handle.is_null() {
                return Err(error_text(&error));
            }
            // From here on, Drop closes the handle on every error path.
            let link = datalink(handle);
            let cap = Self {
                api,
                handle,
                link,
                _lib: lib,
            };
            let pcap_error = || {
                let text = get_err(handle);
                if text.is_null() {
                    "capture driver error".to_string()
                } else {
                    CStr::from_ptr(text).to_string_lossy().into_owned()
                }
            };
            if link != 1 && !(loopback && link == 0) {
                return Err("Select an Ethernet interface (unsupported link type).".into());
            }
            if let Some(filter) = filter {
                let mut program = BpfProgram {
                    len: 0,
                    insns: std::ptr::null_mut(),
                };
                if compile(handle, &mut program, filter.as_ptr(), 1, NETMASK_UNKNOWN) != 0 {
                    return Err(format!("Capture filter: {}", pcap_error()));
                }
                let applied = set_filter(handle, &mut program);
                free_code(&mut program);
                if applied != 0 {
                    return Err(format!("Capture filter: {}", pcap_error()));
                }
            }
            if nonblock(handle, 1, error.as_mut_ptr()) != 0 {
                return Err(error_text(&error));
            }
            Ok(cap)
        }
    }
    // Not an `Iterator`: `Ok(None)` is a read timeout, not the end, and errors are reported.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.next_timed()?.map(|(_, frame)| frame))
    }
    /// The next frame and its capture time in microseconds since the Unix epoch.
    #[allow(clippy::should_implement_trait)]
    pub fn next_timed(&mut self) -> Result<Option<(u64, Vec<u8>)>, String> {
        unsafe {
            let mut header = std::ptr::null();
            let mut bytes = std::ptr::null();
            match (self.api.next)(self.handle, &mut header, &mut bytes) {
                1 if !header.is_null() && !bytes.is_null() => {
                    let len = (*header).caplen as usize;
                    if len > 65536 {
                        return Err("Oversized capture frame".into());
                    }
                    let micros = ((*header).seconds as i64).max(0) as u64 * 1_000_000
                        + ((*header).micros as i64).max(0) as u64;
                    Ok(Some((
                        micros,
                        std::slice::from_raw_parts(bytes, len).to_vec(),
                    )))
                }
                0 => Ok(None),
                _ => Err("Capture ended or driver error".into()),
            }
        }
    }
    pub fn send(&mut self, packet: &[u8]) -> Result<(), String> {
        unsafe {
            if (self.api.send)(self.handle, packet.as_ptr(), packet.len() as c_int) == 0 {
                Ok(())
            } else {
                Err("Packet send failed".into())
            }
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.handle);
        }
    }
}
/// Read-only capture handle: it exposes no way to transmit, by construction.
pub struct PassiveCapture(Capture);
impl PassiveCapture {
    pub fn open(name: &str) -> Result<Self, String> {
        Capture::open(name).map(Self)
    }
    // Not an `Iterator`: `Ok(None)` is a read timeout, not the end, and errors are reported.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.0.next()
    }
    /// A capture of the traffic to and from some hosts, for `scan --record-wire`: not
    /// promiscuous (only this computer's own traffic), with a kernel filter, Ethernet or
    /// loopback link type. Like the rest of this type it has no way to transmit.
    pub fn open_wire(name: &str, filter: &str) -> Result<Self, String> {
        Capture::open_link(name, false, Some(filter), true).map(Self)
    }
    /// The link type of the capture: 1 Ethernet, 0 loopback (no Ethernet header).
    pub fn link_type(&self) -> u16 {
        self.0.link as u16
    }
    /// The next frame with its capture time in microseconds since the Unix epoch.
    #[allow(clippy::should_implement_trait)]
    pub fn next_timed(&mut self) -> Result<Option<(u64, Vec<u8>)>, String> {
        self.0.next_timed()
    }
}
pub fn mac(text: &str) -> Result<[u8; 6], String> {
    let values: Result<Vec<u8>, _> = text
        .split([':', '-'])
        .map(|x| u8::from_str_radix(x, 16))
        .collect();
    values
        .map_err(|_| "Invalid MAC address".to_string())?
        .try_into()
        .map_err(|_| "MAC must contain six bytes".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LoadLibraryExW with LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR rejects forward slashes, which made
    /// an installed Npcap look missing.
    #[cfg(windows)]
    #[test]
    fn npcap_path_has_only_backslashes() {
        let p = npcap_dll_path(Some(r"C:\Windows".into()));
        let s = p.to_string_lossy();
        assert_eq!(s, r"C:\Windows\System32\Npcap\wpcap.dll");
        assert!(!s.contains('/'));
        assert!(npcap_dll_path(None).is_absolute());
    }

    #[test]
    fn library_candidates_cover_macos_and_linux() {
        let mac = library_candidates(true);
        assert_eq!(mac[0], "libpcap.A.dylib");
        assert!(mac.contains(&"libpcap.dylib"));
        let linux = library_candidates(false);
        assert_eq!(linux[0], "libpcap.so.1");
        assert!(linux.iter().all(|n| !n.ends_with(".dylib")));
    }

    #[test]
    fn error_buffer_uses_platform_c_char() {
        // `[0i8; 256]` did not compile where c_char is u8 (aarch64 Linux).
        let mut error: ErrorBuffer = [0; 256];
        for (i, b) in b"no such device".iter().enumerate() {
            error[i] = c_char::from_ne_bytes([*b]);
        }
        assert_eq!(error_text(&error), "no such device");
        let full: ErrorBuffer = [c_char::from_ne_bytes(*b"x"); 256];
        assert_eq!(
            error_text(&full).len(),
            256,
            "unterminated buffer stays in bounds"
        );
    }

    #[test]
    fn syn_filter_selects_tcp_to_source() {
        assert_eq!(
            syn_filter("10.0.0.9".parse().unwrap(), &[]),
            "tcp and dst host 10.0.0.9"
        );
        assert_eq!(
            syn_filter(
                "10.0.0.9".parse().unwrap(),
                &["fe80::5".parse().unwrap(), "2001:db8::5".parse().unwrap()]
            ),
            "tcp and (dst host 10.0.0.9 or dst host fe80::5 or dst host 2001:db8::5)"
        );
    }
}
