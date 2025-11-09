# AMSI/ETW Detect BOF

## Summary

This Beacon Object File (BOF) checks for AMSI and ETW presence in the current process by detecting loaded DLLs (`clr.dll`, `coreclr.dll`, `System.Management.Automation.dll`) and ETW-related exports.

### Example Output

```
CLR_DLL: true CORECLR_DLL: true PS_DLL: true ADVAPI_DLL: true EVENT_WRITE: true EVENT_FULL: true NTDLL_DLL: true ETW_WRITE: true ETW_FULL: false
```
