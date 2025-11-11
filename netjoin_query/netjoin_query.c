#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGetJoinInformation(LPCWSTR lpServer, LPWSTR *lpNameBuffer, PNETSETUP_JOIN_STATUS BufferType);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetWkstaGetInfo(LPWSTR servername, DWORD level, LPBYTE *bufptr);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOEXW lpVersionInformation);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static int wide_to_utf8(LPCWSTR src, char *dst, int dstSize) {
    int result;

    if (dst == NULL || dstSize <= 0) {
        return 0;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return 1;
    }

    result = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstSize, NULL, NULL);
    if (result == 0) {
        int i = 0;
        while (src[i] != L'\0' && i < (dstSize - 1)) {
            dst[i] = (char)(src[i] & 0xFF);
            i++;
        }
        dst[i] = '\0';
        result = i + 1;
    }

    return result;
}

static const char *join_status_text(NETSETUP_JOIN_STATUS status) {
    switch (status) {
        case NetSetupUnknownStatus:
            return "Unknown";
        case NetSetupUnjoined:
            return "Unjoined";
        case NetSetupWorkgroupName:
            return "Workgroup";
        case NetSetupDomainName:
            return "Domain";
        default:
            return "Other";
    }
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;

    LPWSTR joinName = NULL;
    NETSETUP_JOIN_STATUS joinStatus = NetSetupUnknownStatus;
    NET_API_STATUS status;
    char buffer[256];
    int converted;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Querying join information...\n");

    status = NETAPI32$NetGetJoinInformation(NULL, &joinName, &joinStatus);
    if (status == NERR_Success && joinName != NULL) {
        inline_memset(buffer, 0, sizeof(buffer));
        converted = wide_to_utf8(joinName, buffer, sizeof(buffer));
        if (converted > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Join Type: %s\n", join_status_text(joinStatus));
            BeaconPrintf(CALLBACK_OUTPUT, "Join Name: %s\n", buffer);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert join name to UTF-8 (status %lu)\n", (unsigned long)status);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] NetGetJoinInformation failed with status %lu\n", (unsigned long)status);
    }

    if (joinName != NULL) {
        NETAPI32$NetApiBufferFree(joinName);
    }

    {
        LPBYTE wkstaBuffer = NULL;
        PWKSTA_INFO_100 wkstaInfo;

        status = NETAPI32$NetWkstaGetInfo(NULL, 100, &wkstaBuffer);
        if (status == NERR_Success && wkstaBuffer != NULL) {
            wkstaInfo = (PWKSTA_INFO_100)wkstaBuffer;

            inline_memset(buffer, 0, sizeof(buffer));
            if (wide_to_utf8(wkstaInfo->wki100_computername, buffer, sizeof(buffer)) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "Computer Name: %s\n", buffer);
            }

            inline_memset(buffer, 0, sizeof(buffer));
            if (wide_to_utf8(wkstaInfo->wki100_langroup, buffer, sizeof(buffer)) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "Logon Domain: %s\n", buffer);
            }

            NETAPI32$NetApiBufferFree(wkstaBuffer);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] NetWkstaGetInfo failed with status %lu\n", (unsigned long)status);
        }
    }

    {
        RTL_OSVERSIONINFOEXW osInfo;
        inline_memset(&osInfo, 0, sizeof(osInfo));
        osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
        
        if (NTDLL$RtlGetVersion(&osInfo) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "OS Version: %lu.%lu.%lu", 
                (unsigned long)osInfo.dwMajorVersion, 
                (unsigned long)osInfo.dwMinorVersion,
                (unsigned long)osInfo.dwBuildNumber);
            
            if (osInfo.dwMajorVersion == 10 && osInfo.dwMinorVersion == 0) {
                if (osInfo.dwBuildNumber >= 22000) {
                    BeaconPrintf(CALLBACK_OUTPUT, " (Windows 11)\n");
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, " (Windows 10)\n");
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "\n");
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] RtlGetVersion failed\n");
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] query completed\n");
}
