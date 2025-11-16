#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

static void* inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
    return dest;
}

static void* inline_memcpy(void *dest, const void *src, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (count--) {
        *d++ = *s++;
    }
    return dest;
}

static void query_string_value(HKEY hKey, const char *valueName, char *output, DWORD outputSize) {
    DWORD type;
    DWORD dataSize = outputSize;
    LONG result;
    
    inline_memset(output, 0, outputSize);
    result = ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)output, &dataSize);
    
    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        output[0] = '\0';
    }
}

static DWORD query_dword_value(HKEY hKey, const char *valueName, DWORD defaultValue) {
    DWORD type;
    DWORD data;
    DWORD dataSize = sizeof(DWORD);
    LONG result;
    
    result = ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)&data, &dataSize);
    
    if (result != ERROR_SUCCESS || type != REG_DWORD) {
        return defaultValue;
    }
    
    return data;
}

static const char* get_enforcement_mode(DWORD mode) {
    switch (mode) {
        case 0: return "NotConfigured";
        case 1: return "Enforced";
        case 2: return "AuditOnly";
        default: return "Unknown";
    }
}

static void build_collection_path(const char *collectionName, char *buffer, size_t bufferSize) {
    const char base[] = "SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\";
    size_t i = 0;
    size_t j = 0;

    if (bufferSize == 0) {
        return;
    }

    inline_memset(buffer, 0, bufferSize);

    while (i + 1 < bufferSize && base[i] != '\0') {
        buffer[i] = base[i];
        i++;
        if (i >= 80) {
            break;
        }
    }

    while (i + 1 < bufferSize && collectionName[j] != '\0') {
        buffer[i] = collectionName[j];
        i++;
        j++;
        if (j >= 64) {
            break;
        }
    }

    buffer[i] = '\0';
}

static void build_rule_path(const char *collectionPath, const char *ruleGuid, char *buffer, size_t bufferSize) {
    size_t i = 0;
    size_t j = 0;

    if (bufferSize == 0) {
        return;
    }

    inline_memset(buffer, 0, bufferSize);

    while (i + 1 < bufferSize && collectionPath[j] != '\0') {
        buffer[i] = collectionPath[j];
        i++;
        j++;
        if (i >= 400) {
            break;
        }
    }

    if (i + 1 < bufferSize) {
        buffer[i++] = '\\';
    }

    j = 0;
    while (i + 1 < bufferSize && ruleGuid[j] != '\0') {
        buffer[i] = ruleGuid[j];
        i++;
        j++;
        if (j >= 256) {
            break;
        }
    }

    buffer[i] = '\0';
}

static void check_rule_collection(const char *collectionName, const char *displayName) {
    HKEY hKey;
    LONG result;
    char fullPath[512];
    DWORD dwValue;
    DWORD subKeyCount = 0;
    DWORD index = 0;
    char ruleGuid[256];
    DWORD ruleGuidSize;
    HKEY hRuleKey;
    char ruleName[512];
    char rulePath[768];
    
    build_collection_path(collectionName, fullPath, sizeof(fullPath));

    result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hKey);

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %s: not configured\n", displayName);
        return;
    }

    dwValue = query_dword_value(hKey, "EnforcementMode", 0xFFFFFFFF);
    result = ADVAPI32$RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s: %s, %lu rules\n", displayName, get_enforcement_mode(dwValue), (unsigned long)subKeyCount);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s: configured, %lu rules\n", displayName, (unsigned long)subKeyCount);
    }

    while (index < subKeyCount && index < 100) {
        ruleGuidSize = sizeof(ruleGuid);
        inline_memset(ruleGuid, 0, sizeof(ruleGuid));
        
        result = ADVAPI32$RegEnumKeyExA(hKey, index, ruleGuid, &ruleGuidSize, NULL, NULL, NULL, NULL);
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result == ERROR_SUCCESS) {
            build_rule_path(fullPath, ruleGuid, rulePath, sizeof(rulePath));
            
            result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, rulePath, 0, KEY_READ, &hRuleKey);
            if (result == ERROR_SUCCESS) {
                inline_memset(ruleName, 0, sizeof(ruleName));
                query_string_value(hRuleKey, "Name", ruleName, sizeof(ruleName));
                
                if (ruleName[0] != '\0') {
                    BeaconPrintf(CALLBACK_OUTPUT, "    %s: %s\n", ruleGuid, ruleName);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "    %s\n", ruleGuid);
                }
                
                ADVAPI32$RegCloseKey(hRuleKey);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "    %s\n", ruleGuid);
            }
        }
        
        index++;
    }

    ADVAPI32$RegCloseKey(hKey);
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;

    check_rule_collection("Exe", "Executable Rules");
    check_rule_collection("Dll", "DLL Rules");
    check_rule_collection("Script", "Script Rules");
    check_rule_collection("Msi", "MSI Rules");
    check_rule_collection("Appx", "AppX Rules");
}

