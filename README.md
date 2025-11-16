# Adrenaline BOF Kit
<img src="https://github.com/atomiczsec/Adrenaline/blob/main/Assets/ADRENALINE.jpg" width="100%">

*This repository contains BOFs (Beacon Object Files) designed for various red team and offensive security engagements. The end goal is to have a toolkit of BOFs that we can run interchangeably when looking to orchestrate large scale recon or actions.*

<div align='center'>


| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[app_count](recon/app_count/)**    | Counts the number of installed applications via the registry, de-duplicates, and prints. Applied to a large number of beacons, allows us to infer things about a device based on app count differences. |
| **[amsi_etw_detect](defense_detection/amsi_etw_detect/)**      | Checks for AMSI and ETW presence in the current process by detecting loaded DLLs and ETW-related exports. Useful for picking targets with less security activity when applied broadly.                    |
| **[wsc_status](defense_detection/wsc_status/)**           | Queries Windows Security Center health status, including Anti-Virus, Firewall, Anti-Spyware, WSC Service, Auto-Update, Internet Settings, and User Account Control.                                          |
| **[user_idle](target_prioritization/user_idle/)**            | Gets user idle time since last input and GUI resource usage (GDI/USER handles) in the current process for timing intelligence.                                         |
| **[window_handles_enum](cred_access/window_handles_enum/)**  | Enumerates window handles across all system processes and uses a legitimate window handle to access the clipboard.                                                      |
| **[clipboard_grab](cred_access/clipboard_grab/)**       | Retrieves text data from the Windows clipboard using Win32 APIs and returns the contents to the callback.  Original Code Credits: [@rvrsh3ll](https://github.com/rvrsh3ll/BOF_Collection) |
| **[bitlocker_status](env_assessment/bitlocker_status/)**     | Enumerates BitLocker encryption status, policy configurations, and recovery key backup locations by scanning registry keys.                                             |
| **[applocker_policy](env_assessment/applocker_policy/)**     | Enumerates AppLocker policy configurations, rule collections, and enforcement modes by scanning the relevant registry keys.                                             |
| **[wef_detect](env_assessment/wef_detect/)**           | Detects Windows Event Forwarding (WEF) configuration, which indicates centralized logging. If found, indicates security events are being forwarded to a central server. |
| **[netjoin_query](recon/netjoin_query/)**     | Queries Windows domain join information and workstation details, identifying if the system is domain-joined or in a workgroup.                                             |
---

<h3 align="center">Connect with me:</h3>
<p align="center">
  <a href="https://github.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/github.svg" height="30" width="40" /></a>
  <a href="https://instagram.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/instagram.svg" height="30" width="40" /></a>
  <a href="https://twitter.com/atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/twitter.svg" height="30" width="40" /></a>
  <a href="https://medium.com/@atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/medium.svg" height="30" width="40" /></a>
  <a href="https://youtube.com/@atomiczsec" target="_blank"><img src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/youtube.svg" height="30" width="40" /></a>
</p>

---

**DISCLAIMER:** The creators of this repository are not responsible for any harm or damage that may occur as a result of using the information or code provided in this repository.
By accessing and using this repository, you acknowledge and agree that you do so at your own risk. 
