//! Runtime-loaded capture driver: the portable binary has no Npcap link dependency.
use libloading::Library;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
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
pub struct Capture {
    lib: Library,
    handle: Handle,
}
fn library() -> Result<Library, String> {
    #[cfg(windows)]
    let path = std::path::PathBuf::from(
        std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()),
    )
    .join("System32/Npcap/wpcap.dll");
    #[cfg(not(windows))]
    let path = std::path::PathBuf::from("libpcap.so.1");
    #[cfg(windows)]
    let loaded = unsafe {
        libloading::os::windows::Library::load_with_flags(path, 0x100 | 0x1000).map(Library::from)
    };
    #[cfg(not(windows))]
    let loaded = unsafe { Library::new(path) };
    loaded.map_err(|e| format!("Capture driver unavailable (install Npcap on Windows): {e}"))
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
        let mut error = [0i8; 256];
        if find(&mut first, error.as_mut_ptr()) != 0 {
            return Err(CStr::from_ptr(error.as_ptr())
                .to_string_lossy()
                .into_owned());
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
impl Capture {
    pub fn open(name: &str) -> Result<Self, String> {
        if name.is_empty() {
            return Err("Select a capture interface first.".into());
        }
        unsafe {
            let lib = library()?;
            let name = CString::new(name).map_err(|e| e.to_string())?;
            let open = lib.get::<unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> Handle>(b"pcap_open_live\0").map_err(|e| e.to_string())?;
            let mut error = [0i8; 256];
            let handle = open(name.as_ptr(), 65536, 1, 50, error.as_mut_ptr());
            if handle.is_null() {
                return Err(CStr::from_ptr(error.as_ptr())
                    .to_string_lossy()
                    .into_owned());
            }
            let cap = Self { lib, handle };
            let datalink = cap
                .lib
                .get::<unsafe extern "C" fn(Handle) -> c_int>(b"pcap_datalink\0")
                .map_err(|e| e.to_string())?;
            if datalink(handle) != 1 {
                return Err("Select an Ethernet interface (unsupported link type).".into());
            }
            let nonblock = cap
                .lib
                .get::<unsafe extern "C" fn(Handle, c_int, *mut c_char) -> c_int>(
                    b"pcap_setnonblock\0",
                )
                .map_err(|e| e.to_string())?;
            if nonblock(handle, 1, error.as_mut_ptr()) != 0 {
                return Err(CStr::from_ptr(error.as_ptr())
                    .to_string_lossy()
                    .into_owned());
            }
            Ok(cap)
        }
    }
    pub fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        unsafe {
            let next = self
                .lib
                .get::<unsafe extern "C" fn(Handle, *mut *const Header, *mut *const u8) -> c_int>(
                    b"pcap_next_ex\0",
                )
                .map_err(|e| e.to_string())?;
            let mut header = std::ptr::null();
            let mut bytes = std::ptr::null();
            match next(self.handle, &mut header, &mut bytes) {
                1 if !header.is_null() && !bytes.is_null() => {
                    let len = (*header).caplen as usize;
                    if len > 65536 {
                        return Err("Oversized capture frame".into());
                    }
                    Ok(Some(std::slice::from_raw_parts(bytes, len).to_vec()))
                }
                0 => Ok(None),
                _ => Err("Capture ended or driver error".into()),
            }
        }
    }
    pub fn send(&mut self, packet: &[u8]) -> Result<(), String> {
        unsafe {
            let send = self
                .lib
                .get::<unsafe extern "C" fn(Handle, *const u8, c_int) -> c_int>(
                    b"pcap_sendpacket\0",
                )
                .map_err(|e| e.to_string())?;
            if send(self.handle, packet.as_ptr(), packet.len() as c_int) == 0 {
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
            if let Ok(close) = self
                .lib
                .get::<unsafe extern "C" fn(Handle)>(b"pcap_close\0")
            {
                close(self.handle);
            }
        }
    }
}
/// Read-only capture handle: it exposes no way to transmit, by construction.
pub struct PassiveCapture(Capture);
impl PassiveCapture {
    pub fn open(name: &str) -> Result<Self, String> {
        Capture::open(name).map(Self)
    }
    pub fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.0.next()
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
