# Scheduled Task Enumeration (`schtask_enum`)

## Overview

This BOF enumerates scheduled tasks on Windows systems using the Task Scheduler COM interface. It provides a summary of tasks including their state, schedule, and configuration without overwhelming the beacon with XML data, which the legacy version failed to handle.

**Original Source**: [TrustedSec CS-Situational-Awareness-BOF (`schtaskenum`)](https://github.com/trustedsec/CS-Situational-Awareness-BOF)

## Output

```
[i] Enumerating scheduled tasks...

[i] Folder: \

[+] Task: GoogleUpdateTaskMachineCore
[+] Path: \GoogleUpdateTaskMachineCore
[i] Enabled: Yes
[i] State: READY
[i] Last Run: 11/16/2025 10:30:00 AM
[i] Next Run: 11/16/2025 11:30:00 AM

[+] Task: MicrosoftEdgeUpdateTaskMachineUA
[+] Path: \MicrosoftEdgeUpdateTaskMachineUA
[i] Enabled: Yes
[i] State: READY
[i] Last Run: 11/16/2025 9:00:00 AM
[i] Next Run: 11/17/2025 9:00:00 AM

[i] Folder: \Microsoft\Windows\WindowsUpdate

[+] Task: Scheduled Start
[+] Path: \Microsoft\Windows\WindowsUpdate\Scheduled Start
[i] Enabled: Yes
[i] State: DISABLED
[i] Last Run: Never
[i] Next Run: Disabled

[i] Total tasks enumerated: 42
```
