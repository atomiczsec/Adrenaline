# event_log_manage

## Start Here

Run this first to inspect a channel without changing it:

```text
execute-coff -Coff event_log_manage.x64.o -Function go -Arguments string:"inspect" -Arguments string:"Application"
```

Then choose one path:

1. **Read only:** use `inspect` or `sources`.
2. **Write an event:** confirm the classic source with `sources`, then use `write` or `write_raw`.
3. **Manage a custom log:** use `create`, work with the log, then use `destroy` when finished.

> `create`, `clear`, and `destroy` change the host. Run them only from an elevated Administrator or SYSTEM context.

## What This BOF Does

Inspects Windows Event Log channel configuration, creates classic custom logs and sources, enumerates registered sources, writes text or raw binary events through existing classic sources, clears channels with `EvtClearLog`, and removes only custom logs stamped as owned by this BOF.

`write` and `write_raw` target **classic Event Logs** (`RegisterEventSource` / `ReportEvent`). They do not publish into modern provider-driven Event Channels.

## Pick the Correct API Path

Classic Event Logs and modern Event Channels are different APIs.

| Target | Use | This BOF can |
|---|---|---|
| Classic log and registered source | `RegisterEventSource` / `ReportEvent` | Create a custom log, enumerate sources, and write text or binary events. |
| Modern provider-driven channel | `EventWrite` and provider metadata | Inspect or clear the channel only. It cannot inject events. |
| Security log | Security auditing APIs | Inspect or clear with sufficient rights. It cannot write with `ReportEvent`. |

### Classic logs and sources

`RegisterEventSource(NULL, L"<source>")` looks up the source under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<log>\<source>`. The Event Log service chooses the destination `.evtx` from that registration. `ReportEvent` then writes insertion strings and optional `lpRawData`.

If the source is missing, Windows falls back to Application. This BOF refuses that fallback and requires the source to already be registered under the named log.

### Modern Event Channels

Vista+ channels such as `Microsoft-Windows-*/Operational` are owned by a manifest/ETW provider. `EventWrite` publishes according to that provider's registered metadata. The channel is not a free-form `ReportEvent` target. This BOF does not register providers or call `EventWrite`.

`create` still makes a BOF-owned classic log and source for controlled storage. `write` / `write_raw` can use that source or any other registered classic source, including built-in logs such as Application or Key Management Service.

## Choose an Action

Arguments are parsed in the following order. String arguments are ANSI/UTF-8 C2 strings. `write_raw` `data` must be packed as binary so embedded NUL bytes survive.

| Action | Arguments in parse order | Result |
|---|---|---|
| `inspect` | `<channel>` | Prints the complete available channel configuration: identity, isolation, ownership, access SDDL, logging policy/path, publishing filters, ETW buffering, clock/SID modes, file limits, and publisher list. |
| `create` | `<log> <source> [max_size_bytes]` | Registers a new classic custom log and source. Default size is 1 MiB; values are rounded to 64 KiB and capped at 1 GiB. |
| `sources` | `<log>` | Enumerates registered classic sources under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<log>`. Output is capped at 64 names. |
| `write` | `<log> <source> <text>` | Writes a normal textual event through a source that is already registered under that classic log. Payloads are limited to 12,288 UTF-8 bytes. |
| `write_raw` | `<log> <source> <event_id> <category> <data>` | Writes arbitrary binary data through `ReportEvent(..., lpRawData)` to an existing registered source. `event_id` and `category` are packed as `int32`. Raw data is capped at 8,192 bytes. |
| `clear` | `<channel> [backup_path]` | Clears the channel, optionally exporting its current contents first. Application, System, and Security require a backup path. |
| `destroy` | `<log> <source>` | Clears and unregisters a BOF-owned custom log, then attempts to remove its backing `.evtx` file. |

### Name rules

For `create` and `destroy`, custom log and source names may contain letters, digits, spaces, `.`, `-`, and `_`. The names must differ. Built-in logs and `Microsoft-Windows-*` names cannot be created or destroyed.

`write` and `write_raw` accept any registered classic source under the named log, subject to the current token's access rights. They refuse the Security log and refuse sources that are not registered under the specified log.

## Quick Start: Safe Read-Only Check

1. Inspect the Application channel:

   ```text
   execute-coff -Coff event_log_manage.x64.o -Function go -Arguments string:"inspect" -Arguments string:"Application"
   ```

2. List its registered classic sources:

   ```text
   execute-coff -Coff event_log_manage.x64.o -Function go -Arguments string:"sources" -Arguments string:"Application"
   ```

3. Stop here if you only needed configuration or source discovery.

## Example Output

```text
[+] Registered custom log CustomBOF-Demo with source CustomBOF-Demo-Source
[i] max_size=1048576 retention=overwrite owner=event_log_manage-v1
[+] Submitted the initial materialization event
[!] Event Log service caching can delay visibility of a newly registered source
```

```text
[+] Classic Event Log: Application
[+] source[0]=Application
[+] source[1]=SideBySide
[i] sources=2
```

```text
[+] Wrote event to Application with source Application
[i] event_id=2 payload_utf8_bytes=36 payload_utf16_chars=36 raw_bytes=0
```

```text
[+] Wrote raw event to Application with source Application
[i] event_id=1 category=0x4142 raw_bytes=1 insertion_strings=0
[!] Raw Event Log records are readable by anyone who can query that classic log
```

Insufficient permission is reported with an operator-facing elevation hint:

```text
[-] RegCreateKeyExW failed: 5
[!] Permission denied: create requires an elevated Administrator or SYSTEM context with write access to HKLM\SYSTEM\CurrentControlSet\Services\EventLog
```

```text
[+] Channel: CustomBOF-Demo
[i] enabled=1 type=Admin(0) isolation=Application(0) classic=1
[i] owning_publisher=<not configured>
[i] access=O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;BO)(A;;0x1;;;IU)(A;;0x1;;;SU)(A;;0x1;;;S-1-5-3)
[i] retention=0 auto_backup=0 max_size_bytes=1048576
[i] file=C:\Windows\System32\Winevt\Logs\CustomBOF-Demo.evtx
[i] publishing_level=<not configured> publishing_keywords=<not configured>
[i] control_guid=<not configured>
[i] buffer_size_kb=-1 min_buffers=-1 max_buffers=-1 latency_ms=-1
[i] clock_type=-1 sid_type=-1 file_max=-1
[i] publishers=0
```

```text
[+] Cleared CustomBOF-Demo
[!] Event-log clearing is auditable and may be forwarded off-host
[+] Removed owned log and source registration for CustomBOF-Demo
[!] Registration was removed, but the Event Log service retained the backing file: C:\Windows\System32\Winevt\Logs\CustomBOF-Demo.evtx (error 32)
```

## Operational Notes

- Use an elevated Administrator or SYSTEM context for host changes. Clearing is auditable; backup paths must be absolute and must not already exist.
- `create` and `destroy` operate only on BOF-owned registrations. `write` requires a registered classic source; use `write_raw` for binary data larger than text-friendly payloads.

## Scope Limits

- Local classic logs only: no remote sessions, modern-channel injection, or Security-log writes.
- One event is submitted per call with no chunking. C2 argument limits and Event Log service caching still apply.
