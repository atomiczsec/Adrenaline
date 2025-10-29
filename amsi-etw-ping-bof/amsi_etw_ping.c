#include "beacon.h"


static inline const char* yn(int b) { return b ? "Yes" : "No"; }


static inline int has_export(LPCWSTR modW, LPCSTR nameA) {
    HMODULE m = KERNEL32$GetModuleHandleW(modW);
    if (!m) return FALSE;
    return KERNEL32$GetProcAddress(m, nameA) ? TRUE : FALSE;
}

void go(char *args, unsigned long alen) {
    (void)args; (void)alen;
  
    int amsi_dll    = (KERNEL32$GetModuleHandleW(L"amsi.dll") != (HMODULE)0);
    int amsi_api    = has_export(L"amsi.dll", "AmsiScanBuffer");

    int clr_dll    = (KERNEL32$GetModuleHandleW(L"clr.dll") != (HMODULE)0);
    int coreclr_dll = (KERNEL32$GetModuleHandleW(L"coreclr.dll") != (HMODULE)0);
    int ps_dll    = (KERNEL32$GetModuleHandleW(L"System.Management.Automation.dll") != (HMODULE)0);


    int advapi_dll  = (KERNEL32$GetModuleHandleW(L"advapi32.dll") != (HMODULE)0);
    int event_write = has_export(L"advapi32.dll", "EventWrite");
    int event_full  = has_export(L"advapi32.dll", "EventWriteFull");

    int ntdll_dll   = (KERNEL32$GetModuleHandleW(L"ntdll.dll") != (HMODULE)0);
    int etw_write   = has_export(L"ntdll.dll", "EtwEventWrite");
    int etw_full    = has_export(L"ntdll.dll", "EtwEventWriteFull");


    BeaconPrintf(
        CALLBACK_OUTPUT,
        "AMSI_DLL=%s AMSI_API=%s CLR_DLL=%s CORECLR_DLL=%s PS_DLL=%s ADVAPI_DLL=%s EVENTWRITE=%s EVENTWRITEFULL=%s NTDLL_DLL=%s ETW_EVENTWRITE=%s ETW_EVENTWRITEFULL=%s",
        yn(amsi_dll), yn(amsi_api), yn(clr_dll), yn(coreclr_dll), yn(ps_dll), yn(advapi_dll), yn(event_write), yn(event_full), yn(ntdll_dll), yn(etw_write), yn(etw_full)
    );
}