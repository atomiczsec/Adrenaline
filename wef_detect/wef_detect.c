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
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
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

static void check_policy_subscriptions() {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    char valueName[256];
    char valueData[512];
    DWORD valueNameSize;
    DWORD valueDataSize;
    DWORD valueType;
    int subscriptionCount = 0;
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== WEF Policy Subscriptions ===\n");
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No WEF policy subscriptions found\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] WEF subscription policy registry found\n");
    
    while (1) {
        valueNameSize = sizeof(valueName);
        valueDataSize = sizeof(valueData);
        inline_memset(valueName, 0, sizeof(valueName));
        inline_memset(valueData, 0, sizeof(valueData));
        
        result = ADVAPI32$RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL, &valueType, (LPBYTE)valueData, &valueDataSize);
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
            subscriptionCount++;
            if (valueData[0] != '\0') {
                BeaconPrintf(CALLBACK_OUTPUT, "    Subscription %d: %s -> %s\n", subscriptionCount, valueName, valueData);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "    Subscription %d: %s\n", subscriptionCount, valueName);
            }
        }
        
        index++;
        if (index > 100) break;
    }
    
    ADVAPI32$RegCloseKey(hKey);
    
    if (subscriptionCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No subscriptions configured\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Total policy subscriptions: %d\n", subscriptionCount);
    }
}

static void enumerate_collector_subscriptions() {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    char subKeyName[256];
    DWORD subKeyNameSize;
    int subscriptionCount = 0;
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== Event Collector Subscriptions ===\n");
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\EventCollector\\Subscriptions",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Event Collector subscriptions registry not found\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[i] WEF collector service may not be configured\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Event Collector subscriptions found\n");
    
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
        
        if (subKeyNameSize > 0) {
            HKEY hSubKey;
            char fullPath[512];
            char valueBuffer[512];
            DWORD dwValue;
            
            inline_memset(fullPath, 0, sizeof(fullPath));
            
            int i = 0;
            const char *base = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\EventCollector\\Subscriptions\\";
            while (base[i] && i < 400) {
                fullPath[i] = base[i];
                i++;
            }
            int j = 0;
            while (subKeyName[j] && i < 500) {
                fullPath[i++] = subKeyName[j++];
            }
            fullPath[i] = '\0';
            
            result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hSubKey);
            if (result == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Subscription: %s\n", subKeyName);
                
                query_string_value(hSubKey, "Description", valueBuffer, sizeof(valueBuffer));
                if (valueBuffer[0] != '\0') {
                    BeaconPrintf(CALLBACK_OUTPUT, "    Description: %s\n", valueBuffer);
                }
                
                query_string_value(hSubKey, "Uri", valueBuffer, sizeof(valueBuffer));
                if (valueBuffer[0] != '\0') {
                    BeaconPrintf(CALLBACK_OUTPUT, "    URI: %s\n", valueBuffer);
                }
                
                query_string_value(hSubKey, "ConfigurationMode", valueBuffer, sizeof(valueBuffer));
                if (valueBuffer[0] != '\0') {
                    BeaconPrintf(CALLBACK_OUTPUT, "    Configuration Mode: %s\n", valueBuffer);
                }
                
                dwValue = query_dword_value(hSubKey, "Enabled", 0xFFFFFFFF);
                if (dwValue != 0xFFFFFFFF) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    Enabled: %s\n", dwValue ? "Yes" : "No");
                }
                
                dwValue = query_dword_value(hSubKey, "DeliveryMode", 0xFFFFFFFF);
                if (dwValue != 0xFFFFFFFF) {
                    const char *mode = "Unknown";
                    if (dwValue == 0) mode = "Push";
                    else if (dwValue == 1) mode = "Pull";
                    BeaconPrintf(CALLBACK_OUTPUT, "    Delivery Mode: %s (%lu)\n", mode, (unsigned long)dwValue);
                }
                
                ADVAPI32$RegCloseKey(hSubKey);
                subscriptionCount++;
            }
        }
        
        index++;
        if (index > 100) break;
    }
    
    ADVAPI32$RegCloseKey(hKey);
    
    if (subscriptionCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No active subscriptions found\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Total active subscriptions: %d\n", subscriptionCount);
    }
}

static void check_forwarder_configuration() {
    HKEY hKey;
    LONG result;
    DWORD dwValue;
    char valueBuffer[512];
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== WEF Forwarder Configuration ===\n");
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No WEF forwarder policies configured\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] WEF forwarder policy registry found\n");
    
    dwValue = query_dword_value(hKey, "ConfigureForwardingResourceUsage", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Resource Usage Configured: %s\n", dwValue ? "Yes" : "No");
    }
    
    query_string_value(hKey, "SubscriptionManagerPolicy", valueBuffer, sizeof(valueBuffer));
    if (valueBuffer[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "    Subscription Manager Policy: %s\n", valueBuffer);
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Windows Event Forwarding (WEF) Detector\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Checking for centralized logging configuration...\n");
    
    check_policy_subscriptions();
    enumerate_collector_subscriptions();
    check_forwarder_configuration();
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] WEF detection completed.\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[!] If WEF is configured, logs are being forwarded to a central server\n");
}

