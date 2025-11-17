# ASR Status BOF

## Summary

Enumerates Windows Defender Attack Surface Reduction (ASR) rules from registry locations to identify which ASR rules are configured, their enforcement state (Block/Audit/Warn/Disabled), and the policy source (Intune/MDM vs Group Policy).


## Output

```
[+] Windows Defender service: Automatic
[+] Real-Time Protection: Enabled

[+] Intune/MDM ASR Rules (Policy Manager):
    [Block] Block credential stealing from LSASS (lsass.exe)
        GUID: 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 | State: 1
    [Audit] Block Office apps from creating executable content
        GUID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A | State: 2

[-] No GPO ASR rules found (Exploit Guard)

[+] Defender Policy Manager (serialized policy data found):
    PolicyRules value present (size: 4523 bytes)
```

### State Values

- **0**: Disabled
- **1**: Block (enforcement mode - blocks actions and generates alerts)
- **2**: Audit (logs events but allows actions to proceed)
- **6**: Warn (prompts user with option to proceed)
