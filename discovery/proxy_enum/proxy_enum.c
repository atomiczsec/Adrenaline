#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "beacon.h"

#ifndef BOOL
typedef int BOOL;
#endif

#define BUF_SIZE_SMALL  256
#define BUF_SIZE_MEDIUM 512
#define BUF_SIZE_LARGE  1024
#define FILE_SCAN_SIZE  16384
#define SECTION_SCAN_SIZE 1536

#define WINHTTP_ACCESS_TYPE_NO_PROXY           1
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY        3
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY    4

typedef struct {
    DWORD  dwAccessType;
    LPWSTR lpszProxy;
    LPWSTR lpszProxyBypass;
    LPWSTR lpszAutoConfigUrl;
} WINHTTP_PROXY_INFO;

static void CheckRegistryProxy(void);
static void CheckPolicyAndMachineProxy(void);
static void CheckWinHttpProxy(void);
static void CheckWinHttpBinarySettings(void);
static void CheckEnvProxy(void);
static void CheckSystemEnvironmentProxy(void);
static void CheckTelemetryProxy(void);
static void CheckWPAD(void);
static void CheckChromeProxy(void);
static void CheckDotNetProxy(void);

DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI KERNEL32$GlobalFree(HLOCAL);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO *);

static void inline_memset(void *ptr, int value, size_t num) {
    unsigned char *p = (unsigned char *)ptr;
    while (num-- > 0) {
        *p++ = (unsigned char)value;
    }
}

static DWORD ascii_strlen(const char *text) {
    DWORD len = 0;

    if (!text) {
        return 0;
    }

    while (text[len] != '\0') {
        len++;
    }

    return len;
}

static char ascii_tolower(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return (char)(ch + ('a' - 'A'));
    }
    return ch;
}

static BOOL is_ascii_space(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static BOOL strings_equal_ci(const char *left, const char *right) {
    DWORD i = 0;

    while (left[i] != '\0' && right[i] != '\0') {
        if (ascii_tolower(left[i]) != ascii_tolower(right[i])) {
            return FALSE;
        }
        i++;
    }

    return left[i] == '\0' && right[i] == '\0';
}

static const char *find_substring_ci(const char *haystack, const char *needle) {
    DWORD i;
    DWORD j;
    DWORD needleLen = ascii_strlen(needle);

    if (!haystack || !needle || needleLen == 0) {
        return haystack;
    }

    for (i = 0; haystack[i] != '\0'; i++) {
        for (j = 0; j < needleLen; j++) {
            if (haystack[i + j] == '\0') {
                return NULL;
            }
            if (ascii_tolower(haystack[i + j]) != ascii_tolower(needle[j])) {
                break;
            }
        }
        if (j == needleLen) {
            return haystack + i;
        }
    }

    return NULL;
}

static void safe_copy(char *dst, DWORD dstSize, const char *src) {
    DWORD i = 0;

    if (dstSize == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    while (src[i] != '\0' && i < dstSize - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static BOOL safe_append(char *dst, DWORD dstSize, const char *src) {
    DWORD dstLen = ascii_strlen(dst);
    DWORD i = 0;

    if (dstLen >= dstSize) {
        return FALSE;
    }

    while (src[i] != '\0' && dstLen + i < dstSize - 1) {
        dst[dstLen + i] = src[i];
        i++;
    }

    if (src[i] != '\0') {
        dst[dstSize - 1] = '\0';
        return FALSE;
    }

    dst[dstLen + i] = '\0';
    return TRUE;
}

static void copy_window(char *dst, DWORD dstSize, const char *src, DWORD maxChars) {
    DWORD i = 0;

    if (dstSize == 0) {
        return;
    }

    while (src[i] != '\0' && i < maxChars && i < dstSize - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static BOOL query_registry_string(HKEY hKey, const char *valueName, char *output, DWORD outputSize) {
    DWORD type;
    DWORD dataSize = outputSize;
    LONG result;

    inline_memset(output, 0, outputSize);
    result = ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)output, &dataSize);

    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        output[0] = '\0';
        return FALSE;
    }

    if (outputSize > 0) {
        output[outputSize - 1] = '\0';
    }
    return TRUE;
}

static DWORD query_registry_dword(HKEY hKey, const char *valueName, DWORD defaultValue) {
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

static BOOL query_registry_dword_value(HKEY hKey, const char *valueName, DWORD *valueOut) {
    DWORD type;
    DWORD data;
    DWORD dataSize = sizeof(DWORD);
    LONG result;

    result = ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)&data, &dataSize);

    if (result != ERROR_SUCCESS || type != REG_DWORD) {
        return FALSE;
    }

    *valueOut = data;
    return TRUE;
}

static BOOL query_registry_binary(HKEY hKey, const char *valueName, BYTE *output, DWORD *outputSize) {
    DWORD type;
    DWORD dataSize = *outputSize;
    LONG result;

    inline_memset(output, 0, *outputSize);
    result = ADVAPI32$RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)output, &dataSize);

    if (result != ERROR_SUCCESS || type != REG_BINARY) {
        *outputSize = 0;
        return FALSE;
    }

    *outputSize = dataSize;
    return TRUE;
}

static BOOL read_text_file_prefix(const char *path, char *output, DWORD outputSize) {
    HANDLE hFile;
    DWORD bytesRead = 0;
    DWORD fileSize;
    DWORD toRead;

    if (outputSize == 0) {
        return FALSE;
    }

    output[0] = '\0';

    hFile = KERNEL32$CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    toRead = outputSize - 1;
    if (fileSize < toRead) {
        toRead = fileSize;
    }

    if (toRead == 0) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    if (!KERNEL32$ReadFile(hFile, output, toRead, &bytesRead, NULL) || bytesRead == 0) {
        KERNEL32$CloseHandle(hFile);
        output[0] = '\0';
        return FALSE;
    }

    output[bytesRead] = '\0';
    KERNEL32$CloseHandle(hFile);
    return TRUE;
}

static BOOL query_environment_variable(const char *varName, char *output, DWORD outputSize, BOOL *wasTruncated) {
    DWORD result;

    inline_memset(output, 0, outputSize);
    if (wasTruncated) {
        *wasTruncated = FALSE;
    }

    result = KERNEL32$GetEnvironmentVariableA(varName, output, outputSize);
    if (result == 0) {
        output[0] = '\0';
        return FALSE;
    }

    if (result >= outputSize) {
        output[outputSize - 1] = '\0';
        if (wasTruncated) {
            *wasTruncated = TRUE;
        }
    }

    return TRUE;
}

static BOOL extract_json_value(const char *text, const char *key, char *output, DWORD outputSize) {
    const char *cursor;
    DWORD i = 0;

    if (outputSize == 0) {
        return FALSE;
    }

    output[0] = '\0';
    cursor = find_substring_ci(text, key);
    if (!cursor) {
        return FALSE;
    }

    while (*cursor != '\0' && *cursor != ':') {
        cursor++;
    }
    if (*cursor != ':') {
        return FALSE;
    }

    cursor++;
    while (is_ascii_space(*cursor)) {
        cursor++;
    }

    if (*cursor == '"') {
        cursor++;
        while (*cursor != '\0' && *cursor != '"' && i < outputSize - 1) {
            output[i++] = *cursor++;
        }
        output[i] = '\0';
        return i > 0;
    }

    while (*cursor != '\0' &&
           *cursor != ',' &&
           *cursor != '}' &&
           *cursor != '\r' &&
           *cursor != '\n' &&
           i < outputSize - 1) {
        output[i++] = *cursor++;
    }

    while (i > 0 && is_ascii_space(output[i - 1])) {
        i--;
    }
    output[i] = '\0';
    return i > 0;
}

static BOOL extract_xml_attribute(const char *text, const char *attribute, char *output, DWORD outputSize) {
    const char *cursor;
    char quote;
    DWORD i = 0;

    if (outputSize == 0) {
        return FALSE;
    }

    output[0] = '\0';
    cursor = find_substring_ci(text, attribute);
    if (!cursor) {
        return FALSE;
    }

    while (*cursor != '\0' && *cursor != '=') {
        cursor++;
    }
    if (*cursor != '=') {
        return FALSE;
    }

    cursor++;
    while (is_ascii_space(*cursor)) {
        cursor++;
    }

    quote = *cursor;
    if (quote != '"' && quote != '\'') {
        return FALSE;
    }
    cursor++;

    while (*cursor != '\0' && *cursor != quote && i < outputSize - 1) {
        output[i++] = *cursor++;
    }
    output[i] = '\0';
    return i > 0;
}

static void CheckRegistryProxy(void) {
    HKEY hKey;
    DWORD dwProxyEnable;
    char szProxyServer[BUF_SIZE_SMALL];
    char szAutoConfigURL[BUF_SIZE_SMALL];
    char szProxyOverride[BUF_SIZE_MEDIUM];

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying Registry (HKCU) / WinINET Proxy Settings...\n");

    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwProxyEnable = query_registry_dword(hKey, "ProxyEnable", 0);
        BeaconPrintf(CALLBACK_OUTPUT, "  - Proxy Enabled: %s\n", dwProxyEnable ? "Yes" : "No");

        if (dwProxyEnable) {
            if (query_registry_string(hKey, "ProxyServer", szProxyServer, sizeof(szProxyServer))) {
                BeaconPrintf(CALLBACK_OUTPUT, "  - Proxy Server: %s\n", szProxyServer);
            }

            if (query_registry_string(hKey, "ProxyOverride", szProxyOverride, sizeof(szProxyOverride))) {
                BeaconPrintf(CALLBACK_OUTPUT, "  - Proxy Bypass: %s\n", szProxyOverride);
            }
        }

        if (query_registry_string(hKey, "AutoConfigURL", szAutoConfigURL, sizeof(szAutoConfigURL))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - PAC File (AutoConfigURL): %s\n", szAutoConfigURL);
        }

        ADVAPI32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not open registry key\n");
    }
}

static void PrintPolicyScope(HKEY rootKey, const char *scopeLabel) {
    HKEY hKey;
    DWORD dwValue;
    char szProxyServer[BUF_SIZE_SMALL];
    char szProxyOverride[BUF_SIZE_MEDIUM];
    char szAutoConfigURL[BUF_SIZE_SMALL];

    if (ADVAPI32$RegOpenKeyExA(rootKey, "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    if (query_registry_dword_value(hKey, "ProxySettingsPerUser", &dwValue)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Policy ProxySettingsPerUser: %lu %s\n",
            scopeLabel,
            (unsigned long)dwValue,
            dwValue ? "(user-specific allowed)" : "(enforced per-machine)");
    }

    if (query_registry_dword_value(hKey, "ProxyEnable", &dwValue)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Policy Proxy Enabled: %s\n", scopeLabel, dwValue ? "Yes" : "No");
    }

    if (query_registry_string(hKey, "ProxyServer", szProxyServer, sizeof(szProxyServer))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Policy Proxy Server: %s\n", scopeLabel, szProxyServer);
    }

    if (query_registry_string(hKey, "ProxyOverride", szProxyOverride, sizeof(szProxyOverride))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Policy Proxy Bypass: %s\n", scopeLabel, szProxyOverride);
    }

    if (query_registry_string(hKey, "AutoConfigURL", szAutoConfigURL, sizeof(szAutoConfigURL))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Policy PAC File: %s\n", scopeLabel, szAutoConfigURL);
    }

    ADVAPI32$RegCloseKey(hKey);
}

static void CheckPolicyAndMachineProxy(void) {
    HKEY hKey;
    DWORD dwValue;
    char szProxyServer[BUF_SIZE_SMALL];
    char szProxyOverride[BUF_SIZE_MEDIUM];
    char szAutoConfigURL[BUF_SIZE_SMALL];

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying Machine and Group Policy Proxy Settings...\n");

    PrintPolicyScope(HKEY_LOCAL_MACHINE, "HKLM");
    PrintPolicyScope(HKEY_CURRENT_USER, "HKCU");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (query_registry_dword_value(hKey, "ProxyEnable", &dwValue)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - HKLM Internet Settings Proxy Enabled: %s\n", dwValue ? "Yes" : "No");
        }

        if (query_registry_string(hKey, "ProxyServer", szProxyServer, sizeof(szProxyServer))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - HKLM Internet Settings Proxy Server: %s\n", szProxyServer);
        }

        if (query_registry_string(hKey, "ProxyOverride", szProxyOverride, sizeof(szProxyOverride))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - HKLM Internet Settings Proxy Bypass: %s\n", szProxyOverride);
        }

        if (query_registry_string(hKey, "AutoConfigURL", szAutoConfigURL, sizeof(szAutoConfigURL))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - HKLM Internet Settings PAC File: %s\n", szAutoConfigURL);
        }

        ADVAPI32$RegCloseKey(hKey);
    }
}

static void CheckWinHttpProxy(void) {
    WINHTTP_PROXY_INFO proxyInfo;
    inline_memset(&proxyInfo, 0, sizeof(proxyInfo));

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying WinHTTP Default Proxy...\n");

    if (WINHTTP$WinHttpGetDefaultProxyConfiguration(&proxyInfo)) {
        if (proxyInfo.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - Access Type: Named Proxy\n");
            if (proxyInfo.lpszProxy) {
                BeaconPrintf(CALLBACK_OUTPUT, "  - Proxy Server: %ls\n", proxyInfo.lpszProxy);
            }
            if (proxyInfo.lpszProxyBypass) {
                BeaconPrintf(CALLBACK_OUTPUT, "  - Proxy Bypass: %ls\n", proxyInfo.lpszProxyBypass);
            }
        } else if (proxyInfo.dwAccessType == WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - Access Type: Automatic Proxy\n");
            if (proxyInfo.lpszAutoConfigUrl) {
                BeaconPrintf(CALLBACK_OUTPUT, "  - PAC File: %ls\n", proxyInfo.lpszAutoConfigUrl);
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  - Access Type: Direct (no proxy server)\n");
        }

        if (proxyInfo.lpszProxy) {
            KERNEL32$GlobalFree(proxyInfo.lpszProxy);
        }
        if (proxyInfo.lpszProxyBypass) {
            KERNEL32$GlobalFree(proxyInfo.lpszProxyBypass);
        }
        if (proxyInfo.lpszAutoConfigUrl) {
            KERNEL32$GlobalFree(proxyInfo.lpszAutoConfigUrl);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpGetDefaultProxyConfiguration failed\n");
    }
}

static void CheckWinHttpBinarySettings(void) {
    HKEY hKey;
    BYTE binaryData[BUF_SIZE_LARGE];
    DWORD dwDataSize;

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying WinHTTP Binary Connection Settings...\n");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwDataSize = sizeof(binaryData);
        if (query_registry_binary(hKey, "WinHttpSettings", binaryData, &dwDataSize)) {
            if (dwDataSize >= 16) {
                DWORD dwFlags = *(DWORD *)(binaryData + 8);
                DWORD dwProxyLen = *(DWORD *)(binaryData + 12);
                if (dwFlags == 1 && dwProxyLen == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  - WinHttpSettings: Direct (no proxy) (%d bytes)\n", dwDataSize);
                } else if (dwFlags == 3 && dwProxyLen > 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  - WinHttpSettings: Named Proxy configured (%d bytes) - view with: netsh winhttp show proxy\n", dwDataSize);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "  - WinHttpSettings: Present (%d bytes, flags=0x%lx) - view with: netsh winhttp show proxy\n", dwDataSize, (unsigned long)dwFlags);
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "  - WinHttpSettings: Present (%d bytes, too small to decode)\n", dwDataSize);
            }
        }

        dwDataSize = sizeof(binaryData);
        if (query_registry_binary(hKey, "DefaultConnectionSettings", binaryData, &dwDataSize)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - DefaultConnectionSettings: Present (binary blob, %d bytes)\n", dwDataSize);
        }

        dwDataSize = sizeof(binaryData);
        if (query_registry_binary(hKey, "SavedLegacySettings", binaryData, &dwDataSize)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - SavedLegacySettings: Present (binary blob, %d bytes)\n", dwDataSize);
        }

        ADVAPI32$RegCloseKey(hKey);
    }
}

static void CheckEnvProxy(void) {
    char szHttpProxy[BUF_SIZE_SMALL];
    char szHttpsProxy[BUF_SIZE_SMALL];
    char szAllProxy[BUF_SIZE_SMALL];
    char szNoProxy[BUF_SIZE_MEDIUM];
    BOOL truncated;

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying User-Level Environment Variables...\n");

    if (query_environment_variable("http_proxy", szHttpProxy, sizeof(szHttpProxy), &truncated)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - http_proxy: %s%s\n", szHttpProxy, truncated ? " [truncated]" : "");
    }

    if (query_environment_variable("https_proxy", szHttpsProxy, sizeof(szHttpsProxy), &truncated)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - https_proxy: %s%s\n", szHttpsProxy, truncated ? " [truncated]" : "");
    }

    if (query_environment_variable("ALL_PROXY", szAllProxy, sizeof(szAllProxy), &truncated)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - ALL_PROXY: %s%s\n", szAllProxy, truncated ? " [truncated]" : "");
    }

    if (query_environment_variable("NO_PROXY", szNoProxy, sizeof(szNoProxy), &truncated)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - NO_PROXY: %s%s\n", szNoProxy, truncated ? " [truncated]" : "");
    }
}

static void CheckSystemEnvironmentProxy(void) {
    HKEY hKey;
    char szHttpProxy[BUF_SIZE_SMALL];
    char szHttpsProxy[BUF_SIZE_SMALL];
    char szAllProxy[BUF_SIZE_SMALL];
    char szNoProxy[BUF_SIZE_MEDIUM];

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying System-Wide Environment Variables...\n");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (query_registry_string(hKey, "http_proxy", szHttpProxy, sizeof(szHttpProxy))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - http_proxy (System): %s\n", szHttpProxy);
        }

        if (query_registry_string(hKey, "https_proxy", szHttpsProxy, sizeof(szHttpsProxy))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - https_proxy (System): %s\n", szHttpsProxy);
        }

        if (query_registry_string(hKey, "ALL_PROXY", szAllProxy, sizeof(szAllProxy))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - ALL_PROXY (System): %s\n", szAllProxy);
        }

        if (query_registry_string(hKey, "NO_PROXY", szNoProxy, sizeof(szNoProxy))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - NO_PROXY (System): %s\n", szNoProxy);
        }

        ADVAPI32$RegCloseKey(hKey);
    }
}

static void CheckTelemetryProxy(void) {
    HKEY hKey;
    char szTelemetryProxy[BUF_SIZE_SMALL];

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying Service-Specific Proxy Settings...\n");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Policies\\Microsoft\\Windows\\DataCollection", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (query_registry_string(hKey, "TelemetryProxyServer", szTelemetryProxy, sizeof(szTelemetryProxy))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - Telemetry Proxy Server: %s\n", szTelemetryProxy);
        }

        ADVAPI32$RegCloseKey(hKey);
    }
}

static void CheckWPAD(void) {
    HKEY hKey;
    char szAutoDetect[BUF_SIZE_SMALL];
    BYTE binaryData[BUF_SIZE_LARGE];
    DWORD dwAutoDetect;
    DWORD dwDataSize;

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Querying WPAD (Web Proxy Auto-Discovery) Configuration...\n");

    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwAutoDetect = query_registry_dword(hKey, "AutoDetect", 0);
        BeaconPrintf(CALLBACK_OUTPUT, "  - AutoDetect: %s\n", dwAutoDetect ? "Enabled" : "Disabled");

        if (query_registry_string(hKey, "AutoConfigURL", szAutoDetect, sizeof(szAutoDetect))) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - AutoConfigURL: %s\n", szAutoDetect);
        }

        ADVAPI32$RegCloseKey(hKey);
    }

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwAutoDetect = query_registry_dword(hKey, "DefaultConnectionOptions", 0);
        if (dwAutoDetect != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - WinHttp DefaultConnectionOptions: 0x%08lx\n", (unsigned long)dwAutoDetect);
        }

        dwDataSize = sizeof(binaryData);
        if (query_registry_binary(hKey, "WinHttpSettings", binaryData, &dwDataSize)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  - WinHttp Settings Present (%lu bytes)\n", (unsigned long)dwDataSize);
        }

        ADVAPI32$RegCloseKey(hKey);
    }
}

static void PrintChromePolicyScope(HKEY rootKey, const char *scopeLabel, const char *subPath, const char *subLabel) {
    HKEY hKey;
    char szValue[BUF_SIZE_MEDIUM];

    if (ADVAPI32$RegOpenKeyExA(rootKey, subPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    if (query_registry_string(hKey, "ProxyMode", szValue, sizeof(szValue))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Chrome %s ProxyMode: %s\n", scopeLabel, subLabel, szValue);
    }

    if (query_registry_string(hKey, "ProxyServer", szValue, sizeof(szValue))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Chrome %s ProxyServer: %s\n", scopeLabel, subLabel, szValue);
    }

    if (query_registry_string(hKey, "ProxyPacUrl", szValue, sizeof(szValue))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Chrome %s ProxyPacUrl: %s\n", scopeLabel, subLabel, szValue);
    }

    if (query_registry_string(hKey, "ProxyBypassList", szValue, sizeof(szValue))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - %s Chrome %s ProxyBypassList: %s\n", scopeLabel, subLabel, szValue);
    }

    ADVAPI32$RegCloseKey(hKey);
}

static void PrintChromeProfileProxy(const char *profileName, const char *fileData) {
    const char *proxySection;
    const char *objectStart;
    char section[SECTION_SCAN_SIZE];
    char value[BUF_SIZE_MEDIUM];
    BOOL found = FALSE;

    proxySection = find_substring_ci(fileData, "\"proxy\"");
    if (!proxySection) {
        return;
    }

    objectStart = proxySection;
    while (*objectStart != '\0' && *objectStart != ':') {
        objectStart++;
    }
    if (*objectStart != ':') {
        return;
    }

    objectStart++;
    while (is_ascii_space(*objectStart)) {
        objectStart++;
    }
    if (*objectStart != '{') {
        return;
    }

    copy_window(section, sizeof(section), objectStart, SECTION_SCAN_SIZE - 1);

    if (extract_json_value(section, "\"mode\"", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - Chrome Profile %s Proxy Mode: %s\n", profileName, value);
        found = TRUE;
    }

    if (extract_json_value(section, "\"server\"", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - Chrome Profile %s Proxy Server: %s\n", profileName, value);
        found = TRUE;
    }

    if (extract_json_value(section, "\"pac_url\"", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - Chrome Profile %s Proxy PAC URL: %s\n", profileName, value);
        found = TRUE;
    }

    if (extract_json_value(section, "\"bypass_list\"", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - Chrome Profile %s Proxy Bypass List: %s\n", profileName, value);
        found = TRUE;
    }

    if (!found) {
        BeaconPrintf(CALLBACK_OUTPUT, "  - Chrome Profile %s contains proxy-related preference data\n", profileName);
    }
}

static void CheckChromeProxy(void) {
    char localAppData[BUF_SIZE_MEDIUM];
    char userDataPath[BUF_SIZE_LARGE];
    char searchPattern[BUF_SIZE_LARGE];
    char prefPath[BUF_SIZE_LARGE];
    char fileData[FILE_SCAN_SIZE];
    WIN32_FIND_DATAA findData;
    HANDLE hFind;

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Checking Chrome Proxy Configuration...\n");

    PrintChromePolicyScope(HKEY_LOCAL_MACHINE, "HKLM", "Software\\Policies\\Google\\Chrome", "Policy");
    PrintChromePolicyScope(HKEY_CURRENT_USER, "HKCU", "Software\\Policies\\Google\\Chrome", "Policy");
    PrintChromePolicyScope(HKEY_LOCAL_MACHINE, "HKLM", "Software\\Policies\\Google\\Chrome\\Recommended", "Recommended");
    PrintChromePolicyScope(HKEY_CURRENT_USER, "HKCU", "Software\\Policies\\Google\\Chrome\\Recommended", "Recommended");

    if (!query_environment_variable("LOCALAPPDATA", localAppData, sizeof(localAppData), NULL)) {
        return;
    }

    safe_copy(userDataPath, sizeof(userDataPath), localAppData);
    if (!safe_append(userDataPath, sizeof(userDataPath), "\\Google\\Chrome\\User Data\\")) {
        return;
    }

    safe_copy(searchPattern, sizeof(searchPattern), userDataPath);
    if (!safe_append(searchPattern, sizeof(searchPattern), "*")) {
        return;
    }

    hFind = KERNEL32$FindFirstFileA(searchPattern, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }

        if (strings_equal_ci(findData.cFileName, ".") || strings_equal_ci(findData.cFileName, "..")) {
            continue;
        }

        safe_copy(prefPath, sizeof(prefPath), userDataPath);
        if (!safe_append(prefPath, sizeof(prefPath), findData.cFileName) ||
            !safe_append(prefPath, sizeof(prefPath), "\\Preferences")) {
            continue;
        }

        if (read_text_file_prefix(prefPath, fileData, sizeof(fileData))) {
            PrintChromeProfileProxy(findData.cFileName, fileData);
        }
    } while (KERNEL32$FindNextFileA(hFind, &findData));

    KERNEL32$FindClose(hFind);
}

static void PrintDotNetMachineConfig(const char *label, const char *path) {
    char fileData[FILE_SCAN_SIZE];
    char section[SECTION_SCAN_SIZE];
    char value[BUF_SIZE_MEDIUM];
    const char *proxySection;

    if (!read_text_file_prefix(path, fileData, sizeof(fileData))) {
        return;
    }

    proxySection = find_substring_ci(fileData, "<defaultProxy");
    if (!proxySection) {
        proxySection = find_substring_ci(fileData, "<proxy");
    }
    if (!proxySection) {
        return;
    }

    copy_window(section, sizeof(section), proxySection, SECTION_SCAN_SIZE - 1);

    BeaconPrintf(CALLBACK_OUTPUT, "  - %s machine.config defaultProxy section present\n", label);

    if (extract_xml_attribute(section, "enabled", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "    enabled=%s\n", value);
    }

    if (extract_xml_attribute(section, "usesystemdefault", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "    usesystemdefault=%s\n", value);
    }

    if (extract_xml_attribute(section, "proxyaddress", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "    proxyaddress=%s\n", value);
    }

    if (extract_xml_attribute(section, "scriptlocation", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "    scriptlocation=%s\n", value);
    }

    if (extract_xml_attribute(section, "bypassonlocal", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "    bypassonlocal=%s\n", value);
    }

    if (extract_xml_attribute(section, "autodetect", value, sizeof(value))) {
        BeaconPrintf(CALLBACK_OUTPUT, "    autodetect=%s\n", value);
    }

    if (find_substring_ci(section, "<bypasslist")) {
        BeaconPrintf(CALLBACK_OUTPUT, "    bypasslist present\n");
    }
}

static void CheckDotNetProxy(void) {
    char windir[BUF_SIZE_MEDIUM];
    char path[BUF_SIZE_LARGE];

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Checking .NET Framework Proxy Configuration...\n");

    if (!query_environment_variable("WINDIR", windir, sizeof(windir), NULL)) {
        return;
    }

    safe_copy(path, sizeof(path), windir);
    safe_append(path, sizeof(path), "\\Microsoft.NET\\Framework\\v2.0.50727\\Config\\machine.config");
    PrintDotNetMachineConfig(".NET Framework v2.0.50727", path);

    safe_copy(path, sizeof(path), windir);
    safe_append(path, sizeof(path), "\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\machine.config");
    PrintDotNetMachineConfig(".NET Framework v4.0.30319", path);

    safe_copy(path, sizeof(path), windir);
    safe_append(path, sizeof(path), "\\Microsoft.NET\\Framework64\\v2.0.50727\\Config\\machine.config");
    PrintDotNetMachineConfig(".NET Framework64 v2.0.50727", path);

    safe_copy(path, sizeof(path), windir);
    safe_append(path, sizeof(path), "\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\machine.config");
    PrintDotNetMachineConfig(".NET Framework64 v4.0.30319", path);
}

void go(char *args, unsigned long alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Starting proxy enumeration...\n\n");

    CheckRegistryProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckPolicyAndMachineProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckWinHttpProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckWinHttpBinarySettings();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckEnvProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckSystemEnvironmentProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckTelemetryProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckWPAD();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckChromeProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    CheckDotNetProxy();
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Proxy enumeration complete\n");
}
