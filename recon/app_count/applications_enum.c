#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT LSTATUS ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);


static unsigned long hash_string(const char *s) {
    unsigned long h = 5381;
    unsigned int i = 0;
    unsigned char c = 0;
    if (s == 0) return 0;
    while (i < 1024) {
        c = (unsigned char)s[i++];
        if (c == '\0') break;
        h = ((h << 5) + h) + c;
    }
    return h;
}

void go(char *args, unsigned long alen) {
    HKEY hKey;
    LPCSTR lpSubKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    DWORD dwSubKeys = 0;
    LONG lStatus;

    lStatus = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        lpSubKey,
        0,
        KEY_READ,
        &hKey
    );

    if (lStatus != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open registry key: HKLM\\%s. Error code: %ld", lpSubKey, lStatus);
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    lStatus = ADVAPI32$RegQueryInfoKeyA(
        hKey,
        NULL,
        NULL,
        NULL,
        &dwSubKeys,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (lStatus != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query registry key info. Error code: %ld", lStatus);
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    // de-duplication by counting unique DisplayName values
    {
        #define MAX_TRACKED 256
        unsigned long seenHashes[MAX_TRACKED];
        DWORD seenCount = 0;
        DWORD uniqueCount = 0;

        for (DWORD i = 0; i < dwSubKeys; i++) {
            char subKeyName[256];
            DWORD subKeyLen = sizeof(subKeyName);
            if (ADVAPI32$RegEnumKeyExA(hKey, i, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                continue;
            }

            HKEY hApp = NULL;
            if (ADVAPI32$RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hApp) != ERROR_SUCCESS) {
                uniqueCount++;
                continue;
            }

            char displayName[512];
            DWORD type = 0;
            DWORD nameSize = sizeof(displayName);
            displayName[0] = '\0';
            LSTATUS q = ADVAPI32$RegQueryValueExA(hApp, "DisplayName", NULL, &type, (LPBYTE)displayName, &nameSize);
            ADVAPI32$RegCloseKey(hApp);

            if (q != ERROR_SUCCESS || displayName[0] == '\0') {
                uniqueCount++;
                continue;
            }

            unsigned long h = hash_string(displayName);
            int found = 0;
            for (DWORD j = 0; j < seenCount; j++) {
                if (seenHashes[j] == h) { found = 1; break; }
            }
            if (!found) {
                if (seenCount < MAX_TRACKED) {
                    seenHashes[seenCount++] = h;
                }
                uniqueCount++;
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT, "Number of applications installed: %lu", (unsigned long)uniqueCount);
    }

    ADVAPI32$RegCloseKey(hKey);
}
