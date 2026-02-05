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

static const char* get_encryption_method(DWORD method) {
    switch (method) {
        case 1: return "AES-128";
        case 2: return "AES-256";
        case 3: return "XTS-AES-128";
        case 4: return "XTS-AES-256";
        default: return "Unknown";
    }
}

static const char* get_protection_status(DWORD status) {
    switch (status) {
        case 0: return "Off";
        case 1: return "On";
        case 2: return "Protection Pending";
        case 3: return "Protection Off";
        default: return "Unknown";
    }
}

static void enumerate_bitlocker_volumes() {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    char volumeGuid[256];
    DWORD guidSize;
    int volumeCount = 0;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\BitLockerStatus",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] BitLocker status registry key not found\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[i] BitLocker may not be configured on this system\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== BitLocker Volume Status ===\n");
    
    while (1) {
        guidSize = sizeof(volumeGuid);
        inline_memset(volumeGuid, 0, sizeof(volumeGuid));
        
        result = ADVAPI32$RegEnumKeyExA(hKey, index, volumeGuid, &guidSize, NULL, NULL, NULL, NULL);
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        if (guidSize > 10) {
            HKEY hVolumeKey;
            char fullPath[512];
            char valueBuffer[512];
            DWORD dwValue;
            
            inline_memset(fullPath, 0, sizeof(fullPath));
            
            int i = 0;
            const char *base = "SYSTEM\\CurrentControlSet\\Control\\BitLockerStatus\\";
            while (base[i] && i < 400) {
                fullPath[i] = base[i];
                i++;
            }
            int j = 0;
            while (volumeGuid[j] && i < 500) {
                fullPath[i++] = volumeGuid[j++];
            }
            fullPath[i] = '\0';
            
            result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hVolumeKey);
            if (result == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Volume: %s\n", volumeGuid);
                
                query_string_value(hVolumeKey, "DriveLetter", valueBuffer, sizeof(valueBuffer));
                if (valueBuffer[0] != '\0') {
                    BeaconPrintf(CALLBACK_OUTPUT, "    Drive Letter: %s\n", valueBuffer);
                }
                
                dwValue = query_dword_value(hVolumeKey, "ConversionStatus", 0xFFFFFFFF);
                if (dwValue != 0xFFFFFFFF) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    Conversion Status: %s (%lu)\n", get_protection_status(dwValue), (unsigned long)dwValue);
                }
                
                dwValue = query_dword_value(hVolumeKey, "EncryptionMethod", 0xFFFFFFFF);
                if (dwValue != 0xFFFFFFFF) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    Encryption Method: %s (%lu)\n", get_encryption_method(dwValue), (unsigned long)dwValue);
                }
                
                dwValue = query_dword_value(hVolumeKey, "ProtectionStatus", 0xFFFFFFFF);
                if (dwValue != 0xFFFFFFFF) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    Protection Status: %s (%lu)\n", get_protection_status(dwValue), (unsigned long)dwValue);
                }
                
                dwValue = query_dword_value(hVolumeKey, "VolumeStatus", 0xFFFFFFFF);
                if (dwValue != 0xFFFFFFFF) {
                    const char *volStatus = "Unknown";
                    if (dwValue == 0) volStatus = "FullyDecrypted";
                    else if (dwValue == 1) volStatus = "FullyEncrypted";
                    else if (dwValue == 2) volStatus = "EncryptionInProgress";
                    else if (dwValue == 3) volStatus = "DecryptionInProgress";
                    else if (dwValue == 4) volStatus = "EncryptionPaused";
                    else if (dwValue == 5) volStatus = "DecryptionPaused";
                    BeaconPrintf(CALLBACK_OUTPUT, "    Volume Status: %s (%lu)\n", volStatus, (unsigned long)dwValue);
                }
                
                ADVAPI32$RegCloseKey(hVolumeKey);
                volumeCount++;
            }
        }
        
        index++;
        if (index > 50) break;
    }
    
    ADVAPI32$RegCloseKey(hKey);
    
    if (volumeCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No BitLocker volumes found\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Total volumes: %d\n", volumeCount);
    }
}

static void check_bitlocker_policies() {
    HKEY hKey;
    LONG result;
    DWORD dwValue;
    char valueBuffer[512];
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== BitLocker Policies ===\n");
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\FVE",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No BitLocker policies configured\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] BitLocker policy registry found\n");
    
    dwValue = query_dword_value(hKey, "UseAdvancedStartup", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Use Advanced Startup: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "EnableBDEWithNoTPM", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Enable BDE Without TPM: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "UseTPM", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Use TPM: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "UseTPMPIN", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Use TPM + PIN: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "UseTPMKey", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Use TPM + Key: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "UseTPMKeyPIN", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Use TPM + Key + PIN: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "OSEncryptionType", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    OS Encryption Type: %s (%lu)\n", get_encryption_method(dwValue), (unsigned long)dwValue);
    }
    
    dwValue = query_dword_value(hKey, "FDVEncryptionType", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Fixed Drive Encryption Type: %s (%lu)\n", get_encryption_method(dwValue), (unsigned long)dwValue);
    }
    
    dwValue = query_dword_value(hKey, "RDVEncryptionType", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Removable Drive Encryption Type: %s (%lu)\n", get_encryption_method(dwValue), (unsigned long)dwValue);
    }
    
    dwValue = query_dword_value(hKey, "OSRecovery", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    OS Recovery Enabled: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "OSManageDRAgent", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    AD Recovery Agent: %s\n", dwValue ? "Enabled" : "Disabled");
    }
    
    dwValue = query_dword_value(hKey, "OSRecoveryPassword", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    OS Recovery Password: %s\n", dwValue ? "Required" : "Not Required");
    }
    
    query_string_value(hKey, "OSRecoveryDrive", valueBuffer, sizeof(valueBuffer));
    if (valueBuffer[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "    OS Recovery Drive: %s\n", valueBuffer);
    }
    
    dwValue = query_dword_value(hKey, "FDVDenyWriteAccess", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Deny Write Access to Fixed Drives: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "RDVDenyWriteAccess", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Deny Write Access to Removable Drives: %s\n", dwValue ? "Yes" : "No");
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

static void check_recovery_key_backup() {
    HKEY hKey;
    LONG result;
    DWORD dwValue;
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== Recovery Key Backup ===\n");
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BitLocker",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] BitLocker configuration registry not found\n");
        return;
    }
    
    dwValue = query_dword_value(hKey, "RecoveryKeyBackupToAD", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Backup to Active Directory: %s\n", dwValue ? "Yes" : "No");
    }
    
    dwValue = query_dword_value(hKey, "RecoveryKeyBackupToAzureAD", 0xFFFFFFFF);
    if (dwValue != 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Backup to Azure AD: %s\n", dwValue ? "Yes" : "No");
    }
    
    ADVAPI32$RegCloseKey(hKey);
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] BitLocker Status\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating BitLocker encryption status...\n");
    
    enumerate_bitlocker_volumes();
    check_bitlocker_policies();
    check_recovery_key_backup();
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] BitLocker status check completed.\n");
}

