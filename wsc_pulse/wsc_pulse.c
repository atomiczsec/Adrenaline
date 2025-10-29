#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

enum WSC_SECURITY_PROVIDER {
    WSC_SECURITY_PROVIDER_FIREWALL            = 0x1,
    WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 0x2,
    WSC_SECURITY_PROVIDER_ANTIVIRUS           = 0x4,
    WSC_SECURITY_PROVIDER_ANTISPYWARE         = 0x8,
    WSC_SECURITY_PROVIDER_INTERNET_SETTINGS   = 0x10,
    WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL= 0x20,
    WSC_SECURITY_PROVIDER_SERVICE             = 0x40,
    WSC_SECURITY_PROVIDER_ALL                 = 0x7f
};

enum WSC_SECURITY_PROVIDER_HEALTH {
    WSC_SECURITY_PROVIDER_HEALTH_GOOD         = 0,
    WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED = 1,
    WSC_SECURITY_PROVIDER_HEALTH_POOR         = 2,
    WSC_SECURITY_PROVIDER_HEALTH_SNOOZE       = 3
};

typedef HRESULT (WINAPI *pfnWscGetSecurityProviderHealth)(DWORD, int*);

__forceinline FARPROC gp(LPCWSTR modW, LPCSTR nameA) {
    HMODULE m = KERNEL32$GetModuleHandleW(modW);
    if (!m) m = KERNEL32$LoadLibraryW(modW);
    if (!m) return (FARPROC)0;
    return KERNEL32$GetProcAddress(m, nameA);
}

__forceinline const char* health_str(int h) {
    if (h == WSC_SECURITY_PROVIDER_HEALTH_GOOD)         return "Good";
    if (h == WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED) return "NotMonitored";
    if (h == WSC_SECURITY_PROVIDER_HEALTH_POOR)         return "Poor";
    if (h == WSC_SECURITY_PROVIDER_HEALTH_SNOOZE)       return "Snooze";
    return "Unknown";
}

void go(char *args, unsigned long alen) {
    (void)args; (void)alen;

    pfnWscGetSecurityProviderHealth WscGetSecurityProviderHealth_ =
        (pfnWscGetSecurityProviderHealth) gp(L"wscapi.dll", "WscGetSecurityProviderHealth");

    if (!WscGetSecurityProviderHealth_) {
        BeaconPrintf(CALLBACK_ERROR, "WSC=err:resolver");
        return;
    }

    int hall = -1, hav = -1, hfw = -1, has = -1, hsvc = -1, hau = -1, his = -1, huac = -1;
    HRESULT hr;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_ALL, &hall);
    if (hr != 0) hall = -1;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_ANTIVIRUS, &hav);
    if (hr != 0) hav = -1;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_FIREWALL, &hfw);
    if (hr != 0) hfw = -1;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_ANTISPYWARE, &has);
    if (hr != 0) has = -1;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_SERVICE, &hsvc);
    if (hr != 0) hsvc = -1;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS, &hau);
    if (hr != 0) hau = -1;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_INTERNET_SETTINGS, &his);
    if (hr != 0) his = -1;

    hr = WscGetSecurityProviderHealth_(WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL, &huac);
    if (hr != 0) huac = -1;

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "WSC=ALL:%s AV:%s FW:%s AS:%s SVC:%s AU:%s IS:%s UAC:%s",
        (hall < 0 ? "Unknown" : health_str(hall)),
        (hav < 0  ? "Unknown" : health_str(hav)),
        (hfw < 0  ? "Unknown" : health_str(hfw)),
        (has < 0  ? "Unknown" : health_str(has)),
        (hsvc < 0 ? "Unknown" : health_str(hsvc)),
        (hau < 0  ? "Unknown" : health_str(hau)),
        (his < 0  ? "Unknown" : health_str(his)),
        (huac < 0 ? "Unknown" : health_str(huac))
    );
}

