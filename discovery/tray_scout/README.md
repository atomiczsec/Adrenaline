# tray_scout

Beacon Object File that reports the **taskbar host** executable (`Shell_TrayWnd` owner, typically `explorer.exe`) and enumerates **system tray** notification icons (main area and overflow when present). Optional verbose mode prints **full image paths** for the host and for each icon’s owning process when resolvable.

## Usage

- **Default** (no args): prints taskbar host **exe name** and each tray item **name** (tooltip text), plus owning **exe name** on the same line when the icon’s HWND can be resolved.
- **Verbose**: pass `verbose` or `/verbose` as the packed string argument to also print **full paths** (`TaskbarHostPath`, `TrayItemPath` per item).

### Argument packing (Cobalt Strike)

Empty args:

```
beacon> inline-execute /path/to/tray_scout.x64.o
```

Verbose (pack one string `verbose`):

```
beacon> bof_pack("z", "verbose")
```

### Mythic / other C2

Pack a single length-prefixed string: `verbose` or `/verbose` for paths; omit for names only.

## Example output

```
[i] tray_scout: notification area recon
[+] TaskbarHostExe: explorer.exe
[i] MainTray: 12 tray button(s)
[+] TrayItem: Example Agent | ExampleAgent.exe
[+] TrayItem: Volume
...
[i] Overflow tray not present or not yet created
[i] tray_scout finished
```

Verbose adds lines such as:

```
[+] TaskbarHostPath: C:\Windows\explorer.exe
[+] TrayItemExe: SomeVendor.exe
[+] TrayItemPath: C:\Program Files\Vendor\SomeVendor.exe
```

## Limitations

- Tray toolbar lives inside **explorer.exe** on legacy layouts; the BOF uses `VirtualAllocEx` / `ReadProcessMemory` and may fail if `OpenProcess` is denied.
- **Windows 11 (22H2+)** often removes classic `ToolbarWindow32` tray hosts. When toolbar enumeration fails, `tray_scout` falls back to `HKCU\Control Panel\NotifyIconSettings` (read-only registry metadata).
- Overflow (`NotifyIconOverflowWindow`) may not exist until the user has opened the overflow chevron at least once.
- Per-icon HWND/path resolution on legacy toolbars relies on **undocumented** tray structures and may degrade to tooltip-only lines on some Windows builds.

## Detection

User-mode reads against `explorer.exe` and `SendMessageTimeout` to tray toolbars. Useful for purple-team correlation with process access and desktop session context.
