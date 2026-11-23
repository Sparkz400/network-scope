//! How the desktop window fits into the operating system: its taskbar identity on Windows (the
//! AppUserModelID, which the installer's shortcuts carry too), one window per user session on
//! Windows (a second start brings the first window to the front), and the window size, position
//! and maximized state, remembered in the preferences.
use eframe::egui;
use serde::{Deserialize, Serialize};

/// The AppUserModelID of the window and of the installer's Start menu and desktop shortcuts
/// (installer/network-scope.iss): taskbar pins and the running window group under it. The same
/// name as the winget package identifier.
pub const APP_USER_MODEL_ID: &str = "Sparkz400.NetworkScope";

/// The smallest window (also the viewport's minimum size).
pub const MIN_SIZE: [f32; 2] = [700.0, 400.0];
/// The size of the first window, before any size was saved.
pub const DEFAULT_SIZE: [f32; 2] = [800.0, 450.0];

/// The window's last size and place, in the preferences (`window`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowState {
    /// Content size in logical pixels (without the zoom); 0 until a size was seen.
    pub width: f32,
    pub height: f32,
    /// Top-left corner of the frame in logical pixels; not known on Wayland.
    pub x: Option<f32>,
    pub y: Option<f32>,
    /// The system scale factor when the position was saved, to find it on the monitors again.
    pub scale: f32,
    /// The window was maximized; size and position are those of the normal window.
    pub maximized: bool,
}

impl WindowState {
    /// Takes the window's state from this frame's viewport information. A minimized window and
    /// the size of a maximized one change nothing: the next start restores the normal window.
    /// `zoom` is the interface zoom (egui's rectangles are in zoomed points).
    pub fn observe(&mut self, info: &egui::ViewportInfo, content: egui::Vec2, zoom: f32) {
        if info.minimized == Some(true) || info.fullscreen == Some(true) {
            return;
        }
        if info.maximized == Some(true) {
            self.maximized = true;
            return;
        }
        if info.maximized == Some(false) {
            self.maximized = false;
        }
        // Whole logical pixels, so that a window that did not move does not rewrite the file.
        let size = info.inner_rect.map_or(content, |r| r.size()) * zoom;
        if size.x >= 1.0 && size.y >= 1.0 {
            self.width = size.x.round();
            self.height = size.y.round();
        }
        if let Some(outer) = info.outer_rect {
            self.x = Some((outer.min.x * zoom).round());
            self.y = Some((outer.min.y * zoom).round());
            if let Some(scale) = info.native_pixels_per_point {
                self.scale = scale;
            }
        }
    }

    /// The first window: the saved size (at least [`MIN_SIZE`]), the saved position when it is
    /// still on a monitor, and maximized when it was.
    pub fn apply(&self, builder: egui::ViewportBuilder) -> egui::ViewportBuilder {
        let mut builder = builder;
        if self.width > 0.0 && self.height > 0.0 {
            builder = builder
                .with_inner_size([self.width.max(MIN_SIZE[0]), self.height.max(MIN_SIZE[1])]);
        }
        if let (Some(x), Some(y)) = (self.x, self.y)
            && position_is_visible(x, y, self.scale)
        {
            builder = builder.with_position([x, y]);
        }
        builder.with_maximized(self.maximized)
    }
}

/// Whether a window at this top-left corner (logical pixels) has its title bar on a monitor, so a
/// window saved on a monitor that is gone now opens where the system puts new windows.
#[cfg(windows)]
fn position_is_visible(x: f32, y: f32, scale: f32) -> bool {
    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn MonitorFromPoint(point: Point, flags: u32) -> isize;
    }
    const MONITOR_DEFAULTTONULL: u32 = 0;
    let scale = if scale > 0.0 { scale } else { 1.0 };
    // A spot in the title bar, right of the icon: where the window is grabbed to move it.
    let point = Point {
        x: ((x + 80.0) * scale) as i32,
        y: ((y + 12.0) * scale) as i32,
    };
    // SAFETY: MonitorFromPoint only reads the point passed by value.
    unsafe { MonitorFromPoint(point, MONITOR_DEFAULTTONULL) != 0 }
}
/// Elsewhere the position is left to the system: there is no monitor check before the window
/// exists, and Wayland ignores positions anyway.
#[cfg(not(windows))]
fn position_is_visible(_x: f32, _y: f32, _scale: f32) -> bool {
    false
}

/// Gives this process the taskbar identity [`APP_USER_MODEL_ID`]. Must run before the window is
/// created. Failure only means Windows groups the window by its executable path, as before.
#[cfg(windows)]
pub fn set_app_user_model_id() {
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SetCurrentProcessExplicitAppUserModelID(id: *const u16) -> i32;
    }
    let id = wide(APP_USER_MODEL_ID);
    // SAFETY: `id` is a NUL-terminated UTF-16 string that outlives the call (the system copies it).
    unsafe {
        SetCurrentProcessExplicitAppUserModelID(id.as_ptr());
    }
}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The result of [`claim_single_instance`].
#[cfg(windows)]
pub enum Instance {
    /// This is the only window of this user session; keep the guard until the window closes.
    First(InstanceGuard),
    /// Another window was running and was brought to the front: this process should end.
    Another,
}

/// Owns the named shared memory that marks the running window (closed with the process).
#[cfg(windows)]
pub struct InstanceGuard(#[allow(dead_code)] isize);

/// One window per user session: the first process creates a named shared memory block holding
/// its process ID; a later one finds the block, restores and focuses that process's window and
/// reports [`Instance::Another`]. When the block cannot be opened (for example it belongs to an
/// elevated window and this process is not elevated), this process starts normally.
#[cfg(windows)]
pub fn claim_single_instance() -> Instance {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileMappingW(
            file: isize,
            security: *const c_void,
            protect: u32,
            size_high: u32,
            size_low: u32,
            name: *const u16,
        ) -> isize;
        fn MapViewOfFile(
            mapping: isize,
            access: u32,
            offset_high: u32,
            offset_low: u32,
            bytes: usize,
        ) -> *mut c_void;
        fn UnmapViewOfFile(address: *const c_void) -> i32;
        fn CloseHandle(handle: isize) -> i32;
        fn GetLastError() -> u32;
        fn GetCurrentProcessId() -> u32;
    }
    const INVALID_HANDLE_VALUE: isize = -1;
    const PAGE_READWRITE: u32 = 0x04;
    const FILE_MAP_READ: u32 = 0x04;
    const FILE_MAP_WRITE: u32 = 0x02;
    const ERROR_ALREADY_EXISTS: u32 = 183;
    // "Local\": per user session, so other users on the same machine have their own window.
    let name = wide(&format!("Local\\{APP_USER_MODEL_ID}.Window"));
    // SAFETY: a pagefile-backed mapping of 4 bytes with a NUL-terminated name; the view is only
    // used while mapped and is 4 bytes, the size of the u32 written or read.
    unsafe {
        let mapping = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_READWRITE,
            0,
            4,
            name.as_ptr(),
        );
        if mapping == 0 {
            return Instance::First(InstanceGuard(0));
        }
        let existed = GetLastError() == ERROR_ALREADY_EXISTS;
        if !existed {
            let view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 4);
            if !view.is_null() {
                (view as *mut u32).write_volatile(GetCurrentProcessId());
                UnmapViewOfFile(view);
            }
            return Instance::First(InstanceGuard(mapping));
        }
        let view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 4);
        let pid = if view.is_null() {
            0
        } else {
            let pid = (view as *const u32).read_volatile();
            UnmapViewOfFile(view);
            pid
        };
        CloseHandle(mapping);
        // 0: the first process has not written its ID yet (two starts at once); its window
        // is about to open, so this one still ends.
        if pid != 0 {
            bring_to_front(pid);
        }
        Instance::Another
    }
}

/// Restores (if minimized) and focuses the window of process `pid`: its visible, unowned
/// top-level window of winit's window class (not, in a console build, its console window). A
/// process the user just started may move another process's window to the foreground.
#[cfg(windows)]
fn bring_to_front(pid: u32) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn EnumWindows(
            callback: unsafe extern "system" fn(isize, isize) -> i32,
            data: isize,
        ) -> i32;
        fn GetWindowThreadProcessId(window: isize, pid: *mut u32) -> u32;
        fn IsWindowVisible(window: isize) -> i32;
        fn GetWindow(window: isize, command: u32) -> isize;
        fn GetClassNameW(window: isize, name: *mut u16, capacity: i32) -> i32;
        fn IsIconic(window: isize) -> i32;
        fn ShowWindow(window: isize, command: i32) -> i32;
        fn SetForegroundWindow(window: isize) -> i32;
    }
    const GW_OWNER: u32 = 4;
    const SW_RESTORE: i32 = 9;
    /// The class winit registers its windows under (eframe keeps the default).
    const WINIT_CLASS: &str = "Window Class";
    struct Search {
        pid: u32,
        found: isize,
    }
    unsafe extern "system" fn visit(window: isize, data: isize) -> i32 {
        // SAFETY: `data` is the `Search` passed to EnumWindows below, alive during the call.
        let search = unsafe { &mut *(data as *mut Search) };
        let mut pid = 0;
        // SAFETY: plain queries on a window handle the system just passed in.
        let main = unsafe {
            GetWindowThreadProcessId(window, &mut pid);
            pid == search.pid
                && IsWindowVisible(window) != 0
                && GetWindow(window, GW_OWNER) == 0
                && {
                    let mut class = [0u16; 64];
                    let n = GetClassNameW(window, class.as_mut_ptr(), class.len() as i32);
                    n > 0 && String::from_utf16_lossy(&class[..n as usize]) == WINIT_CLASS
                }
        };
        if main {
            search.found = window;
            return 0;
        }
        1
    }
    let mut search = Search { pid, found: 0 };
    // SAFETY: the callback only touches `search`, which outlives the enumeration.
    unsafe {
        EnumWindows(visit, &mut search as *mut Search as isize);
        if search.found != 0 {
            if IsIconic(search.found) != 0 {
                ShowWindow(search.found, SW_RESTORE);
            }
            SetForegroundWindow(search.found);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(inner: [f32; 4], outer_min: [f32; 2], maximized: bool) -> egui::ViewportInfo {
        egui::ViewportInfo {
            inner_rect: Some(egui::Rect::from_min_size(
                egui::pos2(inner[0], inner[1]),
                egui::vec2(inner[2], inner[3]),
            )),
            outer_rect: Some(egui::Rect::from_min_size(
                egui::pos2(outer_min[0], outer_min[1]),
                egui::vec2(inner[2] + 16.0, inner[3] + 39.0),
            )),
            maximized: Some(maximized),
            minimized: Some(false),
            native_pixels_per_point: Some(1.5),
            ..Default::default()
        }
    }

    #[test]
    fn a_normal_window_is_saved_in_whole_logical_pixels_without_the_zoom() {
        let mut state = WindowState::default();
        let content = egui::vec2(0.0, 0.0);
        state.observe(
            &info([108.0, 239.0, 900.4, 600.0], [100.0, 200.0], false),
            content,
            1.0,
        );
        assert_eq!(
            state,
            WindowState {
                width: 900.0,
                height: 600.0,
                x: Some(100.0),
                y: Some(200.0),
                scale: 1.5,
                maximized: false,
            }
        );
        // Zoom 2: egui's points are half as many; the logical size stays the same.
        let mut zoomed = WindowState::default();
        zoomed.observe(
            &info([54.0, 119.5, 450.2, 300.0], [50.0, 100.0], false),
            content,
            2.0,
        );
        assert_eq!((zoomed.width, zoomed.height), (900.0, 600.0));
        assert_eq!((zoomed.x, zoomed.y), (Some(100.0), Some(200.0)));
    }

    #[test]
    fn maximizing_and_minimizing_keep_the_normal_size_and_place() {
        let mut state = WindowState::default();
        let content = egui::vec2(0.0, 0.0);
        state.observe(
            &info([8.0, 31.0, 900.0, 600.0], [0.0, 0.0], false),
            content,
            1.0,
        );
        let normal = state;
        state.observe(
            &info([0.0, 0.0, 2560.0, 1400.0], [-8.0, -8.0], true),
            content,
            1.0,
        );
        assert!(state.maximized);
        assert_eq!((state.width, state.x), (normal.width, normal.x));
        let mut minimized = info([0.0, 0.0, 160.0, 28.0], [-32000.0, -32000.0], false);
        minimized.minimized = Some(true);
        state.observe(&minimized, content, 1.0);
        assert!(
            state.maximized,
            "minimizing a maximized window keeps it maximized"
        );
        assert_eq!(state.x, normal.x);
        state.observe(
            &info([8.0, 31.0, 900.0, 600.0], [0.0, 0.0], false),
            content,
            1.0,
        );
        assert!(!state.maximized);
    }

    #[test]
    fn without_a_window_position_only_the_size_is_saved() {
        // Wayland: no rectangles; the content size of the frame is used.
        let mut state = WindowState::default();
        let wayland = egui::ViewportInfo {
            maximized: Some(false),
            ..Default::default()
        };
        state.observe(&wayland, egui::vec2(1024.0, 700.0), 1.0);
        assert_eq!((state.width, state.height), (1024.0, 700.0));
        assert_eq!((state.x, state.y), (None, None));
    }

    #[test]
    fn the_installer_shortcuts_carry_the_app_id_of_the_window() {
        let iss =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("installer/network-scope.iss");
        let iss = std::fs::read_to_string(iss).unwrap();
        let entry = format!("AppUserModelID: \"{APP_USER_MODEL_ID}\"");
        assert_eq!(
            iss.matches(&entry).count(),
            2,
            "Start menu and desktop shortcut"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_process_takes_the_app_id() {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn GetCurrentProcessExplicitAppUserModelID(id: *mut *mut u16) -> i32;
        }
        #[link(name = "ole32")]
        unsafe extern "system" {
            fn CoTaskMemFree(memory: *mut std::ffi::c_void);
        }
        set_app_user_model_id();
        let mut id = std::ptr::null_mut();
        // SAFETY: on success the system returns a NUL-terminated string to free with CoTaskMemFree.
        let read = unsafe {
            assert_eq!(GetCurrentProcessExplicitAppUserModelID(&mut id), 0);
            let len = (0..).take_while(|&i| *id.add(i) != 0).count();
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(id, len));
            CoTaskMemFree(id.cast());
            text
        };
        assert_eq!(read, APP_USER_MODEL_ID);
    }

    #[test]
    fn a_saved_position_far_off_every_monitor_is_not_used() {
        assert!(!position_is_visible(-100_000.0, -100_000.0, 1.0));
    }

    #[test]
    fn old_preferences_without_a_window_load_with_the_default_size() {
        let state: WindowState = serde_json::from_str("{}").unwrap();
        assert_eq!(state, WindowState::default());
        let builder = state.apply(egui::ViewportBuilder::default());
        assert_eq!(builder.inner_size, None);
        assert_eq!(builder.position, None);
    }

    #[test]
    fn a_saved_size_below_the_minimum_is_raised_to_it() {
        let state = WindowState {
            width: 300.0,
            height: 900.0,
            ..Default::default()
        };
        let builder = state.apply(egui::ViewportBuilder::default());
        assert_eq!(builder.inner_size, Some(egui::vec2(MIN_SIZE[0], 900.0)));
    }
}
