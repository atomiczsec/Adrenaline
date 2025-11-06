# BitLocker Status BOF

## Summary

This Beacon Object File (BOF) enumerates BitLocker encryption status, policy configurations, and recovery key backup locations by scanning registry keys.

## Example Output

```
[*] BitLocker Status
[*] Enumerating BitLocker status...

=== BitLocker Volume Status ===

[+] Volume: {12345678-1234-1234-1234-123456789012}
    Drive Letter: C:
    Conversion Status: On (1)
    Encryption Method: XTS-AES-256 (4)
    Protection Status: On (1)
    Volume Status: FullyEncrypted (1)

[*] Total volumes: 1

=== BitLocker Policies ===
[+] BitLocker policy registry found
    Use Advanced Startup: Yes
    Use TPM: Yes
    OS Encryption Type: XTS-AES-256 (4)
    OS Recovery Enabled: Yes
    AD Recovery Agent: Enabled
    Backup to Active Directory: Yes
    Backup to Azure AD: No

=== Recovery Key Backup ===
    Backup to Active Directory: Yes
    Backup to Azure AD: No

[*] BitLocker status check completed.
```
