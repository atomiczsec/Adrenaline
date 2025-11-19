# AAD Conditional Access Policy Analyzer BOF

## Summary

This Beacon Object File (BOF) enumerates Azure Active Directory Conditional Access policies and related security configurations by scanning registry keys for policy enforcement settings and MFA requirements.

### Example Output

```
[+] Policy Key: ConditionalAccess
    RequireCompliantDevice = 1
    RequireMFA = 1
    PolicyState = Enabled
    EnforcePolicy = 1
[+] Policy Key: CompliancePolicy
    ComplianceState = 1
    RequireMFA = 1
    DeviceComplianceValue = 2
[+] Policy Key: AuthenticationPolicy
    MFARequired = 1
    EnforceMFA = 1
    PolicyEnforcementState = Active
[+] Policy Key: Authentication
    AadDeviceTrustLevel = 2
    CloudAPRequireMfa = 1
    RequireMFAForSignIn = 1
```

**Value Key:**
- `0` = Disabled/No/False/Off
- `1` = Enabled/Yes/True/On
- `2` = Varies by context (e.g., higher trust level, specific compliance state)
