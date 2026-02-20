#include "beacon.h"

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif
#ifndef WINAPI
#define WINAPI __stdcall
#endif
#ifndef __forceinline
#define __forceinline __inline__ __attribute__((always_inline))
#endif

typedef void*          PVOID;
typedef void*          HANDLE;
typedef void*          HKEY;
typedef unsigned char  BYTE;
typedef unsigned long  DWORD;
typedef long           LONG;
typedef int            BOOL;
typedef const char*    LPCSTR;
typedef DWORD*         LPDWORD;
typedef BYTE*          LPBYTE;
typedef HKEY*          PHKEY;

#ifdef _WIN64
typedef unsigned long long SIZE_T;
#else
typedef unsigned long SIZE_T;
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif

#define ERROR_SUCCESS      0L
#define KEY_READ           0x20019
#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long long)0x80000002)

#define PROCESSOR_ARCHITECTURE_INTEL  0
#define PROCESSOR_ARCHITECTURE_IA64   6
#define PROCESSOR_ARCHITECTURE_AMD64  9
#define PROCESSOR_ARCHITECTURE_ARM64  12

typedef struct {
    unsigned short wProcessorArchitecture;
    unsigned short wReserved;
    DWORD  dwPageSize;
    PVOID  lpMinimumApplicationAddress;
    PVOID  lpMaximumApplicationAddress;
    unsigned long long dwActiveProcessorMask;
    DWORD  dwNumberOfProcessors;
    DWORD  dwProcessorType;
    DWORD  dwAllocationGranularity;
    unsigned short wProcessorLevel;
    unsigned short wProcessorRevision;
} SYSTEM_INFO;

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemInfo(SYSTEM_INFO*);

static __forceinline void* inline_memset(void* dst, int c, unsigned long len) {
    unsigned char* p = (unsigned char*)dst;
    while (len--) *p++ = (unsigned char)c;
    return dst;
}

static BOOL query_reg_str(HKEY hKey, const char *value, char *buffer, DWORD bufferSize) {
    DWORD type = 0;
    DWORD size = bufferSize;
    inline_memset(buffer, 0, bufferSize);
    if (ADVAPI32$RegQueryValueExA(hKey, value, NULL, &type, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
        return TRUE;
    }
    return FALSE;
}

static BOOL query_reg_dword(HKEY hKey, const char *value, DWORD *outValue) {
    DWORD type = 0;
    DWORD size = sizeof(DWORD);
    if (ADVAPI32$RegQueryValueExA(hKey, value, NULL, &type, (LPBYTE)outValue, &size) == ERROR_SUCCESS) {
        return TRUE;
    }
    return FALSE;
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    HKEY hKey = NULL;
    char productName[256];
    char displayVersion[64];
    char currentBuild[64];
    char editionId[64];
    char installType[64];
    DWORD ubr = 0;
    DWORD installDateRaw = 0;
    SYSTEM_INFO sysInfo;
    const char *arch = "Unknown";

    (void)args; (void)alen; (void)parser;

    inline_memset(productName, 0, sizeof(productName));
    inline_memset(displayVersion, 0, sizeof(displayVersion));
    inline_memset(currentBuild, 0, sizeof(currentBuild));
    inline_memset(editionId, 0, sizeof(editionId));
    inline_memset(installType, 0, sizeof(installType));

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open registry key: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\n");
        return;
    }

    query_reg_str(hKey, "ProductName", productName, sizeof(productName));
    if (!query_reg_str(hKey, "DisplayVersion", displayVersion, sizeof(displayVersion))) {
        query_reg_str(hKey, "ReleaseId", displayVersion, sizeof(displayVersion));
    }

    query_reg_str(hKey, "CurrentBuild", currentBuild, sizeof(currentBuild));
    query_reg_str(hKey, "EditionID", editionId, sizeof(editionId));
    query_reg_str(hKey, "InstallationType", installType, sizeof(installType));
    query_reg_dword(hKey, "UBR", &ubr);
    query_reg_dword(hKey, "InstallDate", &installDateRaw);

    ADVAPI32$RegCloseKey(hKey);

    /* Windows 11 fix: ProductName says "Windows 10" even on Win11 (build >= 22000) */
    {
        int build = 0;
        const char *b = currentBuild;
        while (*b >= '0' && *b <= '9') {
            build = build * 10 + (*b - '0');
            b++;
        }
        if (build >= 22000 && productName[8] == '1' && productName[9] == '0') {
            productName[9] = '1';
        }
    }

    inline_memset(&sysInfo, 0, sizeof(sysInfo));
    KERNEL32$GetSystemInfo(&sysInfo);
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "x64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: arch = "ARM64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
        case PROCESSOR_ARCHITECTURE_IA64:  arch = "IA64"; break;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] win_version\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    Product:    %s (%s)\n",
                 productName[0] ? productName : "N/A",
                 displayVersion[0] ? displayVersion : "N/A");
    BeaconPrintf(CALLBACK_OUTPUT, "    Build:      %s.%lu\n",
                 currentBuild[0] ? currentBuild : "N/A",
                 ubr);
    BeaconPrintf(CALLBACK_OUTPUT, "    Edition:    %s | %s\n",
                 editionId[0] ? editionId : "N/A",
                 installType[0] ? installType : "N/A");
    BeaconPrintf(CALLBACK_OUTPUT, "    Arch:       %s\n", arch);

    if (installDateRaw > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    InstallDate: %lu (Unix Timestamp)\n", installDateRaw);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "    InstallDate: N/A\n");
    }
}
