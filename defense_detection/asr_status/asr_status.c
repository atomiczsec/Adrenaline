#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);


typedef enum {
    ASR_STATE_DISABLED = 0,
    ASR_STATE_BLOCK = 1,
    ASR_STATE_AUDIT = 2,
    ASR_STATE_WARN = 6
} ASR_STATE;


typedef struct {
    const char* guid;
    const char* name;
} ASR_RULE;

// Known ASR rules with their GUIDs and descriptions
static const ASR_RULE known_rules[] = {
    {"D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "Block Office apps from creating executable content"},
    {"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "Block Office apps from injecting code into other processes"},
    {"9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "Block credential stealing from LSASS (lsass.exe)"},
    {"56A863A9-875E-4185-98A7-B882C64B5CE5", "Block abuse of exploited vulnerable signed drivers"},
    {"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "Block executable content from email client and webmail"},
    {"01443614-CD74-433A-B99E-2ECDC07BFC25", "Block executable files from running unless they meet prevalence, age, or trusted list criteria"},
    {"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "Block execution of potentially obfuscated scripts"},
    {"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "Block Win32 API calls from Office macros"},
    {"3B576869-A4EC-4529-8536-B80A7769E899", "Block Office apps from creating child processes"},
    {"D3E037E1-3EB8-44C8-A917-57927947596D", "Block JavaScript or VBScript from launching downloaded executable content"},
    {"B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", "Block untrusted and unsigned processes that run from USB"},
    {"26190899-1602-49E8-8B27-EB1D0A1CE869", "Block Office communication apps from creating child processes"},
    {"7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", "Block Adobe Reader from creating child processes"},
    {"E6DB77E5-3DF2-4CF1-B95A-636979351E5B", "Block persistence through WMI event subscription"},
    {"D1E49AAC-8F56-4280-B9BA-993A6D77406C", "Block process creations originating from PSExec and WMI commands"},
    {"33DDEDF1-C6E0-47CB-833E-DE6133960387", "Block ransomware from executing"},
    {"C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB", "Use advanced protection against ransomware"},
    {"A8F5898E-1DC8-49A9-9878-85004B8A61E6", "Block Webshell creation for Servers"}
};

static const int num_known_rules = sizeof(known_rules) / sizeof(ASR_RULE);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static int inline_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

static void inline_strncpy_safe(char *dest, const char *src, size_t dest_size) {
    size_t i;
    if (dest_size == 0) return;
    
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

static void inline_toupper(char *str) {
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = *str - 'a' + 'A';
        }
        str++;
    }
}

static const char* get_rule_name(const char *guid) {
    char upper_guid[64];
    int i;
    
    // validate input length
    if (!guid) return "Unknown ASR Rule";
    
    inline_memset(upper_guid, 0, sizeof(upper_guid));
    inline_strncpy_safe(upper_guid, guid, sizeof(upper_guid));
    inline_toupper(upper_guid);
    
    for (i = 0; i < num_known_rules; i++) {
        char known_upper[64];
        inline_memset(known_upper, 0, sizeof(known_upper));
        inline_strncpy_safe(known_upper, known_rules[i].guid, sizeof(known_upper));
        inline_toupper(known_upper);
        
        if (inline_strcmp(upper_guid, known_upper) == 0) {
            return known_rules[i].name;
        }
    }
    
    return "Unknown ASR Rule";
}

static const char* get_state_string(DWORD state) {
    switch (state) {
        case ASR_STATE_DISABLED: return "Disabled";
        case ASR_STATE_BLOCK:    return "Block";
        case ASR_STATE_AUDIT:    return "Audit";
        case ASR_STATE_WARN:     return "Warn";
        default:                 return "Unknown";
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

static void query_intune_asr_rules(int *found_any) {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    char valueName[256];
    DWORD valueNameSize;
    DWORD valueType;
    DWORD valueData;
    DWORD valueDataSize;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager\\ASR Rules",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] No Intune/MDM ASR rules found (Policy Manager)\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Intune/MDM ASR Rules (Policy Manager):\n");
    *found_any = 1;
    
    while (1) {
        valueNameSize = sizeof(valueName);
        valueDataSize = sizeof(valueData);
        inline_memset(valueName, 0, sizeof(valueName));
        
        result = ADVAPI32$RegEnumValueA(
            hKey,
            index,
            valueName,
            &valueNameSize,
            NULL,
            &valueType,
            (LPBYTE)&valueData,
            &valueDataSize
        );
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        if (valueType == REG_DWORD) {
            const char *ruleName = get_rule_name(valueName);
            const char *stateStr = get_state_string(valueData);
            
            BeaconPrintf(CALLBACK_OUTPUT, "    [%s] %s\n", stateStr, ruleName);
            BeaconPrintf(CALLBACK_OUTPUT, "        GUID: %s | State: %lu\n", valueName, (unsigned long)valueData);
        }
        
        index++;
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

static void query_gpo_asr_rules(int *found_any) {
    HKEY hKey;
    LONG result;
    char valueBuffer[4096];
    DWORD valueSize;
    DWORD valueType;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] No GPO ASR rules found (Exploit Guard)\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] GPO ASR Rules (Exploit Guard):\n");
    *found_any = 1;
    
    valueSize = sizeof(valueBuffer);
    inline_memset(valueBuffer, 0, sizeof(valueBuffer));
    
    result = ADVAPI32$RegQueryValueExA(
        hKey,
        "ExploitGuard_ASR_Rules",
        NULL,
        &valueType,
        (LPBYTE)valueBuffer,
        &valueSize
    );
    
    if (result == ERROR_SUCCESS && valueSize > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    ExploitGuard_ASR_Rules: %s\n", valueBuffer);
        
        // parse the gpo format
        char *ptr = valueBuffer;
        char guid[64];
        int guid_idx = 0;
        int parsing_guid = 1;
        DWORD state_val = 0;
        
        inline_memset(guid, 0, sizeof(guid));
        
        while (*ptr) {
            if (*ptr == '|') {
                if (parsing_guid) {
                    guid[guid_idx] = '\0';
                    parsing_guid = 0;
                    state_val = 0;
                } else {
                    const char *ruleName = get_rule_name(guid);
                    const char *stateStr = get_state_string(state_val);
                    BeaconPrintf(CALLBACK_OUTPUT, "        [%s] %s (GUID: %s)\n", stateStr, ruleName, guid);
                    
                    guid_idx = 0;
                    inline_memset(guid, 0, sizeof(guid));
                    parsing_guid = 1;
                }
                ptr++;
            } else if (parsing_guid) {
                
                if (guid_idx < 63) {
                    guid[guid_idx++] = *ptr;
                }
                ptr++;
            } else {
                if (*ptr >= '0' && *ptr <= '9') {
                    state_val = state_val * 10 + (*ptr - '0');
                }
                ptr++;
            }
        }
        
        if (!parsing_guid && guid_idx > 0) {
            const char *ruleName = get_rule_name(guid);
            const char *stateStr = get_state_string(state_val);
            BeaconPrintf(CALLBACK_OUTPUT, "        [%s] %s (GUID: %s)\n", stateStr, ruleName, guid);
        }
    }
    
    // check for exclusions
    valueSize = sizeof(valueBuffer);
    inline_memset(valueBuffer, 0, sizeof(valueBuffer));
    
    result = ADVAPI32$RegQueryValueExA(
        hKey,
        "ExploitGuard_ASR_ASROnlyExclusions",
        NULL,
        &valueType,
        (LPBYTE)valueBuffer,
        &valueSize
    );
    
    if (result == ERROR_SUCCESS && valueSize > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [+] ASR Exclusions: %s\n", valueBuffer);
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

static void query_defender_policy_manager(int *found_any) {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    char valueName[256];
    DWORD valueNameSize;
    DWORD valueType;
    BYTE valueData[2048];
    DWORD valueDataSize;
    int printed_header = 0;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        return;
    }
    
    while (1) {
        valueNameSize = sizeof(valueName);
        valueDataSize = sizeof(valueData);
        inline_memset(valueName, 0, sizeof(valueName));
        inline_memset(valueData, 0, sizeof(valueData));
        
        result = ADVAPI32$RegEnumValueA(
            hKey,
            index,
            valueName,
            &valueNameSize,
            NULL,
            &valueType,
            valueData,
            &valueDataSize
        );
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        if (inline_strcmp(valueName, "PolicyRules") == 0 && valueDataSize > 0) {
            if (!printed_header) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Defender Policy Manager (serialized policy data found):\n");
                printed_header = 1;
                *found_any = 1;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "    PolicyRules value present (size: %lu bytes)\n", (unsigned long)valueDataSize);
        }
        
        index++;
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

static void check_defender_service_running() {
    HKEY hKey;
    LONG result;
    DWORD startType;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Defender service not found\n");
        return;
    }
    
    startType = query_dword_value(hKey, "Start", 0xFFFFFFFF);
    
    if (startType == 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Defender service: Automatic\n");
    } else if (startType == 3) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Defender service: Manual\n");
    } else if (startType == 4) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Defender service: Disabled\n");
    } else if (startType != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "[?] Defender service start type: %lu\n", (unsigned long)startType);
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

static void check_realtime_protection() {
    HKEY hKey;
    LONG result;
    DWORD disableRealtimeMonitoring;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        return;
    }
    
    disableRealtimeMonitoring = query_dword_value(hKey, "DisableRealtimeMonitoring", 0xFFFFFFFF);
    
    if (disableRealtimeMonitoring == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Real-Time Protection: Enabled\n");
    } else if (disableRealtimeMonitoring == 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Real-Time Protection: Disabled\n");
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;
    
    int found_any = 0;
    
    check_defender_service_running();
    check_realtime_protection();
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    
    query_intune_asr_rules(&found_any);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    
    query_gpo_asr_rules(&found_any);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    
    query_defender_policy_manager(&found_any);
    
    if (!found_any) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] No ASR rules detected in registry\n");
    }
}
