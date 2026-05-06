# Community Inspired BOFs 

The `community/` directory collects BOFs and tools that are from outside this repository (the community) and have been fit to follow the BOF framework constraints:

- No dependency on repository specific framework headers, implementations, or utility libraries
- No CRT
- Standardized output
- Safety caps to avoid hanging

## Current Community Ports

### [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)

| BOF | Description | Original |
| --- | --- | --- |
| [`schtask_enum/`](/community/schtask_enum) | Enumerate scheduled tasks w COM Task Scheduler API, clean output (no xml, which caused BOF to hang) | `schtaskenum` |
| [`net_use/`](/community/net_use) | Add, list, or remove mapped drives via MPR (`WNet*`) with bounded, BOF-safe output handling | `netuse` |

### [SessionView](https://github.com/lsecqt/SessionView) by lsecqt

| BOF | Description | Original |
| --- | --- | --- |
| [`session_view/`](/community/session_view) | Enumerate Windows Terminal Services sessions, displaying session IDs, usernames, domains, connection states, and session LUIDs | `SessionView` |

### [NoteThief](https://github.com/trainr3kt/NoteThief) by trainr3kt

| BOF | Description | Original |
| --- | --- | --- |
| [`notepad_grab/`](/community/notepad_grab) | Extract text content from open Notepad windows | `notethief` |


