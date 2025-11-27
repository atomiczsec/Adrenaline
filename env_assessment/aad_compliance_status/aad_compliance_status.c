#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
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

static void enumerate_enrollment(HKEY hEnrollmentsKey, const char *enrollmentGuid) {
    HKEY hEnrollmentKey;
    LONG result;
    char fullPath[512];
    char valueBuffer[512];
    DWORD dwValue;
    
    inline_memset(fullPath, 0, sizeof(fullPath));
    
    int i = 0;
    const char *base = "SOFTWARE\\Microsoft\\Enrollments\\";
    while (base[i] && i < 400) {
        fullPath[i] = base[i];
        i++;
    }
    int j = 0;
    while (enrollmentGuid[j] && i < 500) {
        fullPath[i++] = enrollmentGuid[j++];
    }
    fullPath[i] = '\0';
    
    result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hEnrollmentKey);
    if (result != ERROR_SUCCESS) {
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] MDM Enrollment Found\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Enrollment GUID: %s\n", enrollmentGuid);
    
    query_string_value(hEnrollmentKey, "DiscoveryServiceFullURL", valueBuffer, sizeof(valueBuffer));
    if (valueBuffer[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Discovery URL: %s\n", valueBuffer);
    }
    
    query_string_value(hEnrollmentKey, "EnrollmentType", valueBuffer, sizeof(valueBuffer));
    if (valueBuffer[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Enrollment Type: %s\n", valueBuffer);
    } else {
        dwValue = query_dword_value(hEnrollmentKey, "EnrollmentType", 0xFFFFFFFF);
        if (dwValue != 0xFFFFFFFF) {
            const char *typeStr = "Unknown";
            if (dwValue == 0) typeStr = "Device";
            else if (dwValue == 6) typeStr = "MDM";
            else if (dwValue == 13) typeStr = "AAD";
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Enrollment Type: %s (%lu)\n", typeStr, (unsigned long)dwValue);
        }
    }
    
    query_string_value(hEnrollmentKey, "ProviderID", valueBuffer, sizeof(valueBuffer));
    if (valueBuffer[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Provider: %s\n", valueBuffer);
    }
    
    query_string_value(hEnrollmentKey, "UPN", valueBuffer, sizeof(valueBuffer));
    if (valueBuffer[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] UPN: %s\n", valueBuffer);
    }
    
    HKEY hMSIKey;
    char msiPath[512];
    inline_memset(msiPath, 0, sizeof(msiPath));
    i = 0;
    while (fullPath[i] && i < 480) {
        msiPath[i] = fullPath[i];
        i++;
    }
    const char *msiSuffix = "\\MS DM Server";
    j = 0;
    while (msiSuffix[j] && i < 500) {
        msiPath[i++] = msiSuffix[j++];
    }
    msiPath[i] = '\0';
    
    result = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, msiPath, 0, KEY_READ, &hMSIKey);
    if (result == ERROR_SUCCESS) {
        query_string_value(hMSIKey, "ServerURL", valueBuffer, sizeof(valueBuffer));
        if (valueBuffer[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Management Server: %s\n", valueBuffer);
            
            if (valueBuffer[0] != '\0') {
                int isIntune = 0;
                for (int k = 0; valueBuffer[k] && k < 400; k++) {
                    if (valueBuffer[k] == 'm' && valueBuffer[k+1] == 'a' && 
                        valueBuffer[k+2] == 'n' && valueBuffer[k+3] == 'a' &&
                        valueBuffer[k+4] == 'g' && valueBuffer[k+5] == 'e') {
                        isIntune = 1;
                        break;
                    }
                }
                if (isIntune) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] Authority: Microsoft Intune\n");
                }
            }
        }
        ADVAPI32$RegCloseKey(hMSIKey);
    }
    
    ADVAPI32$RegCloseKey(hEnrollmentKey);
}

static int enumerate_enrollments() {
    HKEY hEnrollmentsKey;
    LONG result;
    DWORD index = 0;
    char enrollmentGuid[256];
    DWORD guidSize;
    int enrollmentCount = 0;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Enrollments",
        0,
        KEY_READ,
        &hEnrollmentsKey
    );
    
    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open Enrollments registry key (error: %ld)\n", result);
        return 0;
    }
    
    while (1) {
        guidSize = sizeof(enrollmentGuid);
        inline_memset(enrollmentGuid, 0, sizeof(enrollmentGuid));
        
        result = ADVAPI32$RegEnumKeyExA(hEnrollmentsKey, index, enrollmentGuid, &guidSize, NULL, NULL, NULL, NULL);
        
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        if (guidSize > 10) {
            enumerate_enrollment(hEnrollmentsKey, enrollmentGuid);
            enrollmentCount++;
        }
        
        index++;
        if (index > 50) break;
    }
    
    ADVAPI32$RegCloseKey(hEnrollmentsKey);
    return enrollmentCount;
}

static void check_compliance_state() {
    HKEY hKey;
    LONG result;
    char valueBuffer[512];
    DWORD dwValue;
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MDM", // AAD Intune MDM
        0,
        KEY_READ,
        &hKey
    );
    
    if (result == ERROR_SUCCESS) {
        query_string_value(hKey, "DeviceName", valueBuffer, sizeof(valueBuffer));
        if (valueBuffer[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Device Name: %s\n", valueBuffer);
        }
        
        dwValue = query_dword_value(hKey, "IsDeviceManaged", 0xFFFFFFFF);
        if (dwValue != 0xFFFFFFFF) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Device Managed: %s\n", dwValue ? "Yes" : "No");
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
    
    result = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\PolicyManager\\current\\device", // AAD Policy Manager
        0,
        KEY_READ,
        &hKey
    );
    
    if (result == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Policy Manager: Active\n");
        ADVAPI32$RegCloseKey(hKey);
    }
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;
    
    int enrollmentCount = enumerate_enrollments();
    
    if (enrollmentCount > 0) {
        check_compliance_state();
    }
}
