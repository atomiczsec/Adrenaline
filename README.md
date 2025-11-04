# Adrenaline BOF Kit
<img src="https://github.com/atomiczsec/Adrenaline/blob/main/Assets/ADRENALINE.jpg" width="100%">

*This repository contains BOFs (Beacon Object Files) designed for various red team and offensive security engagements. The end goal is to have a toolkit of BOFs that we can run interchangeably when looking to orchestrate large scale recon or actions.*
<div align='center'>

### Quick Reference
  
<a href='https://twitter.com/atomiczsec'>
  
<img src='https://img.shields.io/twitter/follow/atomiczsec?style=social'>
  
</a>
  
<a href='https://github.com/atomiczsec/My-Payloads/'>
  
</a>
  
<a href='https://github.com/atomiczsec/'>
  
<img src='https://img.shields.io/github/followers/atomiczsec?style=social'>
  
</a>
</div>


| **BOF**             | **Use**                                                                                                                                                         |
|------------------------- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **appnumberBOF**         | Counts the number of installed applications via the registry, de-duplicates, and prints. Applied to a large number of beacons, allows us to infer things about a device based on app count differences. |
| **amsi-etw-ping-BOF**    | Checks for AMSI and ETW presence in the current process by detecting loaded DLLs and ETW-related exports. Useful for picking targets with less security activity when applied broadly.                    |
| **wsc_pulse**            | Queries Windows Security Center health status, including Anti-Virus, Firewall, Anti-Spyware, WSC Service, Auto-Update, Internet Settings, and User Account Control.                                          |
| **idle_gui**             | Gets user idle time since last input and GUI resource usage (GDI/USER handles) in the current process for timing intelligence.                                         |
| **enumwindowhandles**    | Enumerates window handles across all system processes and uses a legitimate window handle to access the clipboard.                                                      |
| **clipboardupdated**     | Retrieves text data from the Windows clipboard using Win32 APIs and returns the contents to the callback.  Original Code Credits: [@rvrsh3ll](https://github.com/rvrsh3ll/BOF_Collection) |
  
---

**DISCLAIMER:** The creators of this repository are not responsible for any harm or damage that may occur as a result of using the information or code provided in this repository.
By accessing and using this repository, you acknowledge and agree that you do so at your own risk. 
