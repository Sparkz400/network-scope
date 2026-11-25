# Manual checks

Most of Network Scope is tested automatically (see [Lab and testing](lab-and-testing.md)): CI builds and runs the installer silently, the click tests render real frames of the desktop and click widgets by their accessible names, and the accessibility tree is checked for unnamed controls. Some things still need a person at a real machine. These lists say what to try and what should happen. If you run one, please comment on [issue 12](https://github.com/Sparkz400/network-scope/issues/12) with your system (Windows build, scaling, screen reader and version) and what differed.

## Windows installer

CI covers a silent per-user install, a second install over it, both binaries printing their version, the PATH entry being added once and removed again, and a silent uninstall (`scripts/installer_smoke.ps1`). By hand:

1. **Download and start** `NetworkScope-<version>-setup.exe`. SmartScreen warns, because the installer is not code-signed yet ("More info" → "Run anyway"). The wizard shows the hexagon icon, the license, and the two optional tasks (desktop shortcut, add to PATH).
2. **Install for me only** (the default, no administrator prompt). Expected: Start menu → *Network Scope* starts the app; the taskbar shows the hexagon icon; pinning the running window to the taskbar and starting it from the pin gives **one** taskbar button, not two.
3. **Add to PATH ticked**: a **new** PowerShell or `cmd` window (no sign-out needed) runs `network-scope-cli --version`.
4. **Start it twice**: the second start brings the first window to the front instead of opening another.
5. **Upgrade**: with the app open, run a newer (or the same) installer. Expected: it asks to close the app or closes it, installs over it, keeps your preferences and inventory (`%LOCALAPPDATA%\NetworkScope`), and Settings → Apps lists Network Scope once with the new version.
6. **Install for all users** (choose it in the first dialog; needs administrator rights): installs under `C:\Program Files\Network Scope`, and the Start menu entry is there for other accounts.
7. **Uninstall** from Settings → Apps → Installed apps. Expected: the program folder and the Start menu entries are gone; the PATH entry is gone in a new terminal; `%LOCALAPPDATA%\NetworkScope` (preferences, inventory, feeds) stays, so a reinstall finds your data. Delete that folder yourself to remove everything.

## The desktop in a real window

The click tests drive the app through synthetic frames, and one run drove a real window through UI Automation (see the [GUI guide](gui-guide.md#accessibility)); neither moves a real mouse or reads the screen as a person does. In a real window, at 100 % and at 150 % display scaling:

1. **Sidebar**: each entry shows its icon, name and count; the Findings count has the colour of the worst finding. Tab moves through the entries, Enter opens one. At 800×450 all six entries fit (the list scrolls if the window is shorter).
2. **Hosts page**: **By address** and **By device** switch between the two tables; `Ctrl+3` opens By device and `Ctrl+F` there focuses its filter. Clicking anywhere in a row shows the host details on the right; Up and Down move the selection; `Escape` closes the details.
3. **Columns**: add Manufacturer, Type, OS guess and Risk; each sorts by a click on its header (Risk: worst first). Restart the app: the columns are still there.
4. **Host details**: drag the left edge of the panel; **Timeline** opens the timeline under the page; drag its top edge; its **Close** closes only the timeline.
5. **A scan of your own network** (Overview → **Scan my network**, Safe Mode): rows appear while it runs, the counts update when it ends. For a large range (a /16 in a lab) the Findings count appears a moment after the scan, without the window freezing.
6. **Theme and language**: View → theme dark and light, Settings → Appearance → German; the sidebar, the switch and the timeline are translated and nothing is cut off.
7. **Window placement**: move and resize the window, maximize it, restart: it comes back the same way.
8. **Addresses and sort**: type other addresses, sort the hosts table by another column, restart. Expected: both are as you left them.
9. **Quit during a scan**: start a Safe Mode scan of a /24 and close the window (also `Ctrl+Q`). Expected: **Quit while a scan is running?** appears; **Keep running** continues the scan, **Stop and quit** closes, and the scan is in the inventory as partial after the next start.
10. **A scan that ends in the background**: start a scan, switch to another program. Expected: the taskbar button flashes when the scan ends; a scheduled scan does not flash.
11. **Dropped files**: drop a `.txt` address list on the window (the Addresses field is filled, nothing starts), a `.pcap` (the Passive / OT page opens and reads it) and another file (a message names it).
12. **Passive / OT**: the interface list is filled when the page opens. Choose an interface with empty MAC and IPv4 fields. Expected (Windows): both are filled with the adapter's values (compare with `Get-NetAdapter` and `ipconfig`); typed values are kept until **Use the interface's addresses**.
13. **Inventory**: every row shows its date; **Delete** asks with the scan's targets and date, and the row is gone afterwards; the two pickers and **Compare A to B** list the differences.
15. **Column widths and marked rows**: drag a column border, restart: the column has that width again. Click a host, Shift+click another, right click one of the marked rows: **Copy N rows** puts the rows into the clipboard (paste into a text editor; also copy an address elsewhere and paste it into the Addresses field).
14. **Right click** on a row of Findings and of Hosts by device: the entries copy the address, the finding, the CVE, the evidence and the row; paste into a text editor to check.

## Screen readers

The accessibility tree is checked in tests and was read back through Windows UI Automation, but no one has used the app with a screen reader yet. With **Narrator** (`Win+Ctrl+Enter`), **NVDA**, **Orca** (Linux) or **VoiceOver** (macOS):

1. **Menu bar**: Tab reaches File, Scan, View, Tools, Help; each is read as a menu button and opens with Enter.
2. **Sidebar**: each entry is read with its count ("Findings 10, button, selected" or similar), and the selected one says so.
3. **Hosts table**: each row's address is a focusable control read with its address (★ first for a starred host); Enter shows the details, the menu key opens the host menu. The status is read as a word, not only a colour.
4. **Host details**: section headings (Findings, Services, Actions, All identity fields) are read, collapsed sections say so, and the buttons have names.
5. **Dialogs**: **Turn Safe Mode off?** (Preset → Full audit) takes the focus and is read; `Escape` keeps Safe Mode on.
6. **Text fields**: Addresses, TCP ports, the search and filter boxes are read by their names, not as "edit" alone.
7. **Findings and Hosts by device**: the address at the start of a row is a focusable control read with its text; Enter opens the host (or the device details). In the grouped findings the title is the control.

Report anything read wrongly, read twice, or not read at all.
