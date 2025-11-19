#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"


DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrcmpA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static int string_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    
    int hay_len = KERNEL32$lstrlenA(haystack);
    int needle_len = KERNEL32$lstrlenA(needle);
    
    if (needle_len > hay_len) return 0;
    
    for (int i = 0; i <= hay_len - needle_len; i++) {
        int match = 1;
        for (int j = 0; j < needle_len; j++) {
            char c1 = haystack[i + j];
            char c2 = needle[j];
            if (c1 >= 'A' && c1 <= 'Z') c1 = c1 + 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 = c2 + 32;
            if (c1 != c2) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

static void enumerate_policy_values(HKEY hKey, const char *keyName) {
    DWORD index = 0;
    char valueName[256];
    BYTE valueData[1024];
    DWORD valueNameSize;
    DWORD valueDataSize;
    DWORD valueType;
    LONG result;
    int foundValues = 0;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Policy Key: %s\n", keyName);
    
    while (1) {
        valueNameSize = sizeof(valueName);
        valueDataSize = sizeof(valueData);
        inline_memset(valueName, 0, sizeof(valueName));
        inline_memset(valueData, 0, sizeof(valueData));
        
        result = ADVAPI32$RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL, &valueType, valueData, &valueDataSize);
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        if (string_contains(valueName, "compliant") || 
            string_contains(valueName, "mfa") ||
            string_contains(valueName, "enforce") ||
            string_contains(valueName, "require") ||
            string_contains(valueName, "policy") ||
            string_contains(valueName, "state") ||
            string_contains(valueName, "value")) {
            
            foundValues = 1;
            
            if (valueType == REG_DWORD && valueDataSize == sizeof(DWORD)) {
                DWORD dwValue = *((DWORD*)valueData);
                BeaconPrintf(CALLBACK_OUTPUT, "    %s = %lu\n", valueName, (unsigned long)dwValue);
            } else if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                BeaconPrintf(CALLBACK_OUTPUT, "    %s = %s\n", valueName, (char*)valueData);
            }
        }
        
        index++;
        if (index > 100) break;
    }
}

static int enumerate_policy_keys(HKEY hRootKey, const char *basePath) {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    char subKeyName[256];
    DWORD subKeyNameSize;
    int policiesFound = 0;
    
    result = ADVAPI32$RegOpenKeyExA(hRootKey, basePath, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open registry key: %s (error: %ld)\n", basePath, result);
        return 0;
    }
    
    while (1) {
        subKeyNameSize = sizeof(subKeyName);
        inline_memset(subKeyName, 0, sizeof(subKeyName));
        
        result = ADVAPI32$RegEnumKeyExA(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL);
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        if (string_contains(subKeyName, "conditional") ||
            string_contains(subKeyName, "compliance") ||
            string_contains(subKeyName, "authentication") ||
            string_contains(subKeyName, "mfa") ||
            string_contains(subKeyName, "policy")) {
            
            HKEY hSubKey;
            char fullPath[512];
            inline_memset(fullPath, 0, sizeof(fullPath));
            
            int i = 0;
            while (basePath[i] && i < 400) {
                fullPath[i] = basePath[i];
                i++;
            }
            fullPath[i++] = '\\';
            int j = 0;
            while (subKeyName[j] && i < 500) {
                fullPath[i++] = subKeyName[j++];
            }
            fullPath[i] = '\0';
            
            result = ADVAPI32$RegOpenKeyExA(hRootKey, fullPath, 0, KEY_READ, &hSubKey);
            if (result == ERROR_SUCCESS) {
                enumerate_policy_values(hSubKey, subKeyName);
                ADVAPI32$RegCloseKey(hSubKey);
                policiesFound++;
            }
        }
        
        index++;
        if (index > 200) break;
    }
    
    ADVAPI32$RegCloseKey(hKey);
    return policiesFound;
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;
    
    enumerate_policy_keys(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\PolicyManager\\current\\device"
    );
    
    enumerate_policy_keys(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    );
    
    HKEY hAADKey;
    LONG result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication",
        0,
        KEY_READ,
        &hAADKey
    );
    
    if (result == ERROR_SUCCESS) {
        enumerate_policy_values(hAADKey, "Authentication");
        ADVAPI32$RegCloseKey(hAADKey);
    }
}

