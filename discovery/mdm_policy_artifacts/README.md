# MDM Enrollment & Policy Artifacts Probe BOF

---

## Summary

This Beacon Object File (BOF) uses a scoring model to assess MDM enrollment on Windows systems. It evaluates indicators including join state, scheduled tasks, policy configuration, and enrollment artifacts to produce a posture assessment.

keep in mind this BOF reports only what is observable locally on the endpoint

---

## Scoring Model

The BOF uses a **10-point scoring system** based on multiple independent indicators:

| Indicator | Weight | Description |
|-----------|--------|-------------|
| **dsregcmd /status equivalent** | 3 points | Join state (Azure AD/Hybrid/Workplace) + MDM URL presence |
| **EnterpriseMgmt scheduled tasks** | 2 points | Tasks under `\Microsoft\Windows\EnterpriseMgmt\{GUID}\...` |
| **MDM configuration policy** | 2 points | AutoEnrollMDM GPO policy presence |
| **Intune enrollment evidence** | 2 points | Company Portal or Intune-specific artifacts |
| **Enrollments registry** | 1 point | EnrollmentState/EnrollmentType found in registry |

## Verdicts

* **Enrolled**: Score ≥ 7 points
* **Partially enrolled**: Score 4-6 points
* **Not enrolled**: Score < 4 points

---

### Example Output

```
[+] Indicator: dsregcmd /status equivalent
    Provenance: HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\{GUID}\TenantId
    Value: 11111111-2222-3333-4444-555555555555
    MDM URL: https://enrollment.manage.microsoft.com/...
    Score: +3

[+] Indicator: EnterpriseMgmt scheduled task
    Provenance: Task: \Microsoft\Windows\EnterpriseMgmt\{GUID}\MDM Policy Manager
    Enrollment GUID: {GUID}
    Score: +2

[+] Indicator: MDM configuration policy
    Provenance: HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM\AutoEnrollMDM
    Value: 1
    Score: +2

[+] Indicator: Intune enrollment evidence
    Provenance: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MDM\MDMDeviceID
    Value: {device-id}
    Score: +2

[+] MDM Enrollment Group (GUID: {GUID})
    Provenance: HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}\EnrollmentState
    EnrollmentState: 1
    Provenance: HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}\TenantID
    TenantID: 11111111-2222-3333-4444-555555555555
    Provenance: HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}\DiscoveryServiceFullURL
    DiscoveryServiceFullURL: https://enrollment.manage.microsoft.com/...
    [Correlated from EnterpriseResourceManager\Tracked\{GUID}]
    [Correlated from PolicyManager\providers\{GUID}]

[+] Observed policy artifact: Azure AD authentication plugin enabled: 1
    Provenance: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\EnableAADCloudAPPlugin (Type: REG_DWORD)

[+] Posture Verdict
    MDM posture: Enrolled
    Score: 8/10
```