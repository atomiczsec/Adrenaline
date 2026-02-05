# Adrenaline BOF Kit
<img src="https://github.com/atomiczsec/Adrenaline/blob/main/Assets/ADRENALINE.jpg" width="100%">

*This repository contains BOFs (Beacon Object Files) designed for various red team and offensive security engagements. The end goal is to have a toolkit of BOFs that we can run interchangeably when looking to orchestrate large scale recon or actions.*

<div align='center'>

## Table of Contents (MITRE taxonomy)

[Collection](#collection)  
[Community](#community)  
[Credential Access](#credential-access)  
[Discovery](#discovery)

</div>

## Collection

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[ai_surface](collection/ai_surface/)**     | Maps which AI/Copilot tools are present on an endpoint and reports their key storage locations. Checks for Windows Copilot, Office Copilot, Edge Copilot, GitHub Copilot, and third-party AI tools (ChatGPT, Claude, Cursor IDE). |
| **[clipboard_grab](collection/clipboard_grab/)**       | Retrieves text data from the Windows clipboard using Win32 APIs and returns the contents to the callback.  Original Code Credits: [@rvrsh3ll](https://github.com/rvrsh3ll/BOF_Collection) |
| **[window_handles_enum](collection/window_handles_enum/)**  | Enumerates window handles across all system processes and uses a legitimate window handle to access the clipboard.                                                      |

## Community

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[schtask_enum](community/schtask_enum/)**     | Enumerates scheduled tasks on Windows systems using the Task Scheduler COM interface. Provides a summary of tasks including their state, schedule, and configuration without overwhelming the beacon with XML data. Original Source: [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) |
| **[session_view](community/session_view/)**     | Enumerates Windows Terminal Services sessions, displaying session IDs, usernames, domains, connection states, and session LUIDs. Original Source: [SessionView](https://github.com/lsecqt/SessionView) by lsecqt |

## Credential Access

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[certstore_loot](credential_access/certstore_loot/)**       | Enumerates local certificate stores to find certificates with exportable private keys and provides you with the path to export them. |
| **[process_tokens_list](credential_access/process_tokens_list/)**       | Enumerates accessible tokens from running processes, showing user context, token type (primary/impersonation), and impersonation level. Supports optional filtering by PID or process name. SeDebugPrivilege is disabled by default for OPSEC. |

## Discovery

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[amsi_etw_detect](discovery/amsi_etw_detect/)**      | Checks for AMSI and ETW presence in the current process by detecting loaded DLLs and ETW-related exports. Useful for picking targets with less security activity when applied broadly.                    |
| **[app_count](discovery/app_count/)**    | Counts the number of installed applications via the registry, de-duplicates, and prints. Applied to a large number of beacons, allows us to infer things about a device based on app count differences. |
| **[applocker_policy](discovery/applocker_policy/)**     | Enumerates AppLocker policy configurations, rule collections, and enforcement modes by scanning the relevant registry keys.                                             |
| **[asr_status](discovery/asr_status/)**           | Enumerates Windows Defender Attack Surface Reduction (ASR) rules from registry locations to identify which ASR rules are configured, their enforcement state (Block/Audit/Warn/Disabled), and the policy source (Intune/MDM vs Group Policy).                                          |
| **[bitlocker_status](discovery/bitlocker_status/)**     | Enumerates BitLocker encryption status, policy configurations, and recovery key backup locations by scanning registry keys.                                             |
| **[com_probe](discovery/com_probe/)**           | Probe whether a COM object can be instantiated from a given CLSID. |
| **[mdm_policy_artifacts](discovery/mdm_policy_artifacts/)**           | Uses a scoring model to assess MDM enrollment posture on Windows systems by evaluating indicators including join state, scheduled tasks, policy configuration, and enrollment artifacts. |
| **[netjoin_query](discovery/netjoin_query/)**     | Queries Windows domain join information and workstation details, identifying if the system is domain-joined or in a workgroup. |
| **[user_idle](discovery/user_idle/)**            | Gets user idle time since last input and GUI resource usage (GDI/USER handles) in the current process for timing intelligence.                                         |
| **[wallpaper_enum](discovery/wallpaper_enum/)**     | Enumerates the current desktop wallpaper path for each attached monitor using the modern IDesktopWallpaper COM interface. Centralized wallpapers are sometimes on internal SMB shares or imaging servers, revealing network paths, domain trusts, and policy enforcement without touching disk or the network. |
| **[wef_detect](discovery/wef_detect/)**           | Detects Windows Event Forwarding (WEF) configuration, which indicates centralized logging. If found, indicates security events are being forwarded to a central server. |
| **[wevt_logon_enum](discovery/wevt_logon_enum/)**     | Enumerates recent Security log (successful/failed) logon events (Event IDs 4624,4625,4672) via the wevtapi API and prints remote workstation name/IP plus the target username. |
| **[window_list](discovery/window_list/)**     | Enumerates the titles of all visible windows on the current user's desktop, optionally including Process IDs (PIDs).  |
| **[wsc_status](discovery/wsc_status/)**           | Queries Windows Security Center health status, including Anti-Virus, Firewall, Anti-Spyware, WSC Service, Auto-Update, Internet Settings, and User Account Control.                                          |

---

<h3 align="center">Connect with me:</h3>
<p align="center">
  <a href="https://github.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/github.svg" height="30" width="40" /></a>
  <a href="https://instagram.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/instagram.svg" height="30" width="40" /></a>
  <a href="https://x.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/twitter.svg" height="30" width="40" /></a>
  <a href="https://medium.com/@atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/medium.svg" height="30" width="40" /></a>
  <a href="https://youtube.com/@atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/youtube.svg" height="30" width="40" /></a>
</p>

---

**DISCLAIMER:** The creators and contributors of this repository accept no liability for any loss, damage, or consequences resulting from the use of the information or code contained in this repo. By utilizing this repo, you acknowledge and accept full responsibility for your actions. Use at your own risk.

