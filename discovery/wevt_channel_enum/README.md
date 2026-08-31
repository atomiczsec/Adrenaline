# wevt_channel_enum

## Summary

Enumerates Windows Event Log channels via `EvtOpenChannelEnum` / `EvtNextChannelPath` and dumps each channel's configuration via `EvtOpenChannelConfig` / `EvtGetChannelConfigProperty`.

> **Warning:** Do not run unfiltered. Hosts often have hundreds of low-signal Admin/Analytic/Debug channels; unfiltered runs hit the default `max_channels=256` cap and truncate. Prefer a substring filter such as `PowerShell`, `Scripting`, `Defend`, `Sysmon`, or `WinRM` (see Usage).

## Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `filter` | wstring | No | Case-insensitive substring match on channel path. Empty means all channels. |
| `max_channels` | int | No | Maximum channels to print. Default `256`; hard cap `512`. |
| `flags` | int | No | Bit `0x1` enables verbose output (Access SDDL and publishing level/keywords). |

## Usage

Apollo (`execute_coff`) — prefer a filter; unfiltered runs are noisy:

```text
execute_coff -Coff wevt_channel_enum.x64.o -Function go -Timeout 30 -Arguments wchar:"PowerShell"

execute_coff -Coff wevt_channel_enum.x64.o -Function go -Timeout 30 -Arguments wchar:"Scripting"

execute_coff -Coff wevt_channel_enum.x64.o -Function go -Timeout 30 -Arguments wchar:"Defend"

execute_coff -Coff wevt_channel_enum.x64.o -Function go -Timeout 30 -Arguments wchar:"Sysmon"

execute_coff -Coff wevt_channel_enum.x64.o -Function go -Timeout 30 -Arguments wchar:"WinRM"
```

## Example Output

```text
[i] wevt_channel_enum: enumerating channels
[i] filter=PowerShell max=256 verbose=0
[+] Channel: Microsoft-Windows-PowerShell/Operational
[i]   enabled=1 type=Operational isolation=Application classic=0
[i]   owner=Microsoft-Windows-PowerShell
[i]   path=C:\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx max=15728640 retain=0 autobackup=0
[i] Summary: listed=1 skipped_filter=0 truncated=0
```

Verbose adds:

```text
[i]   access=O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)
[i]   level=4 keywords=0xfffffffffffffff
```

## Operational Notes

- Prefer a substring filter (`PowerShell`, `Scripting`, `Defend`, `Sysmon`, `WinRM`, etc.). Unfiltered enum hits the default `max_channels=256` cap, truncates, and is mostly low-signal Admin/Analytic/Debug channels. See Apollo examples under Usage.
- Dynamically resolves `wevtapi.dll` at runtime; no static link to winevt.

## Limitations

- Enumerates only the local machine; it does not open remote Event Log sessions.
- String properties larger than 2 KiB may be omitted, and output stops at `max_channels`.
