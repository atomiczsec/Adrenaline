# AAD Device Compliance Status BOF

## Summary

This Beacon Object File (BOF) checks Azure Active Directory device compliance status and Intune/MDM enrollment information by querying registry keys for MDM enrollments and compliance state.

### Example Output

```
[+] MDM Enrollment Found

[+] Enrollment GUID: {12345678-1234-1234-1234-123456789abc}
[+] Discovery URL: https://enrollment.manage.microsoft.com/EnrollmentServer/Discovery.svc
[+] Enrollment Type: MDM (6)
[+] Provider: MS DM Server
[+] User UPN: user@company.com
[+] Management Server: https://manage.microsoft.com/
[+] Authority: Microsoft Intune
[+] Device Name: DESKTOP-ABC123
[+] Device Managed: Yes
[+] Policy Manager: Active
```

**Enrollment Type Key:**
- `0` = Device enrollment
- `6` = MDM enrollment
- `13` = Azure AD enrollment

**Device Managed:**
- `Yes` = Device is managed by MDM/Intune
- `No` = Device is not managed
