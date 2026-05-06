#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnetwk.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include "beacon.h"

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef CONNECT_ENCRYPTED
#define CONNECT_ENCRYPTED 0x00000400
#endif

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);
DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

DECLSPEC_IMPORT DWORD WINAPI MPR$WNetAddConnection2W(LPNETRESOURCEW lpNetResource, LPCWSTR lpPassword, LPCWSTR lpUsername, DWORD dwFlags);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetCancelConnection2W(LPCWSTR lpName, DWORD dwFlags, BOOL fForce);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetOpenEnumW(DWORD dwScope, DWORD dwType, DWORD dwUsage, LPNETRESOURCEW lpNetResource, LPHANDLE lphEnum);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetEnumResourceW(HANDLE hEnum, LPDWORD lpcCount, LPVOID lpBuffer, LPDWORD lpBufferSize);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetGetResourceInformationW(LPNETRESOURCEW lpNetResource, LPVOID lpBuffer, LPDWORD lpcbBuffer, LPWSTR *lplpSystem);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetGetUserW(LPCWSTR lpName, LPWSTR lpUserName, LPDWORD lpnLength);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetCloseEnum(HANDLE hEnum);

#define ENUM_BUFFER_SIZE          16384
#define INFO_BUFFER_SIZE          4096
#define STRING_BUFFER_CHARS       260
#define STATUS_BUFFER_CHARS       32
#define MAX_RESOURCE_OUTPUT       256

#define CMD_ADD    1
#define CMD_LIST   2
#define CMD_DELETE 3

static char g_wenum_buffer[ENUM_BUFFER_SIZE];
static char g_winfo_buffer[INFO_BUFFER_SIZE];
static WCHAR g_sc_local[STRING_BUFFER_CHARS];
static WCHAR g_sc_remote[STRING_BUFFER_CHARS];
static WCHAR g_sc_provider[STRING_BUFFER_CHARS];
static WCHAR g_sc_status[STATUS_BUFFER_CHARS];
static WCHAR g_sc_type[STATUS_BUFFER_CHARS];
static WCHAR g_sc_user[STRING_BUFFER_CHARS];
static char g_u8_status[STATUS_BUFFER_CHARS];
static char g_u8_local[STRING_BUFFER_CHARS];
static char g_u8_remote[STRING_BUFFER_CHARS];
static char g_u8_provider[STRING_BUFFER_CHARS];
static char g_u8_type[STATUS_BUFFER_CHARS];
static char g_u8_user[STRING_BUFFER_CHARS];

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count-- != 0U) {
        *d++ = (unsigned char)value;
    }
}

static int wide_to_utf8(LPCWSTR src, char *dst, int dstSize) {
    int converted;

    if (dst == NULL || dstSize <= 0) {
        return 0;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return 1;
    }

    converted = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstSize, NULL, NULL);
    if (converted == 0) {
        int i = 0;
        while (src[i] != L'\0' && i < (dstSize - 1)) {
            dst[i] = (char)(src[i] & 0xFF);
            i++;
        }
        dst[i] = '\0';
        converted = i + 1;
    }

    return converted;
}

static void copy_wide_string(LPWSTR dest, size_t destLen, LPCWSTR src) {
    size_t i = 0;

    if (destLen == 0) {
        return;
    }

    if (src == NULL) {
        dest[0] = L'\0';
        return;
    }

    while (i < (destLen - 1) && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
}

static wchar_t wide_tolower(wchar_t c) {
    if (c >= L'A' && c <= L'Z') {
        return (wchar_t)(c + 32);
    }
    return c;
}

static BOOL wide_equals_ci(LPCWSTR a, LPCWSTR b) {
    if (a == NULL || b == NULL) {
        return FALSE;
    }

    while (*a != L'\0' && *b != L'\0') {
        if (wide_tolower(*a) != wide_tolower(*b)) {
            return FALSE;
        }
        a++;
        b++;
    }

    return (*a == L'\0' && *b == L'\0');
}

static LPWSTR extract_wide_or_null(datap *parser) {
    char *raw = BeaconDataExtract(parser, NULL);
    if (raw == NULL) {
        return NULL;
    }

    if (((LPWSTR)raw)[0] == L'\0') {
        return NULL;
    }

    return (LPWSTR)raw;
}

static void print_windows_error(const char *context, DWORD error) {
    LPSTR message = NULL;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

    if (KERNEL32$FormatMessageA(flags, NULL, error, 0, (LPSTR)&message, 0, NULL) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s (0x%08lx): %s", (context != NULL) ? context : "Windows error", (unsigned long)error, message);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s (0x%08lx)", (context != NULL) ? context : "Windows error", (unsigned long)error);
    }

    if (message != NULL) {
        KERNEL32$LocalFree(message);
    }
}

static const wchar_t *resource_type_name(DWORD type) {
    switch (type) {
        case RESOURCETYPE_DISK:
            return L"Disk";
        case RESOURCETYPE_PRINT:
            return L"Print";
        case RESOURCETYPE_ANY:
            return L"Any";
        default:
            return L"Other";
    }
}

static void print_resource_summary(DWORD index, LPCWSTR status, LPCWSTR local, LPCWSTR remote, LPCWSTR provider, LPCWSTR typeName, LPCWSTR username) {
    wide_to_utf8((status != NULL && status[0] != L'\0') ? status : L"Unknown", g_u8_status, sizeof(g_u8_status));
    wide_to_utf8((local != NULL && local[0] != L'\0') ? local : L"(none)", g_u8_local, sizeof(g_u8_local));
    wide_to_utf8((remote != NULL && remote[0] != L'\0') ? remote : L"(none)", g_u8_remote, sizeof(g_u8_remote));
    wide_to_utf8((provider != NULL && provider[0] != L'\0') ? provider : L"(unknown)", g_u8_provider, sizeof(g_u8_provider));
    wide_to_utf8((typeName != NULL && typeName[0] != L'\0') ? typeName : L"(unknown)", g_u8_type, sizeof(g_u8_type));
    wide_to_utf8((username != NULL && username[0] != L'\0') ? username : L"(not set)", g_u8_user, sizeof(g_u8_user));

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Resource %lu\n", (unsigned long)index);
    BeaconPrintf(CALLBACK_OUTPUT, "    Status   : %s\n", g_u8_status);
    BeaconPrintf(CALLBACK_OUTPUT, "    Type     : %s\n", g_u8_type);
    BeaconPrintf(CALLBACK_OUTPUT, "    Local    : %s\n", g_u8_local);
    BeaconPrintf(CALLBACK_OUTPUT, "    Remote   : %s\n", g_u8_remote);
    BeaconPrintf(CALLBACK_OUTPUT, "    Provider : %s\n", g_u8_provider);
    BeaconPrintf(CALLBACK_OUTPUT, "    User     : %s\n", g_u8_user);
}

static void print_resource_detail(LPCWSTR local, LPCWSTR remote, LPCWSTR typeName, LPCWSTR status, LPCWSTR username) {
    wide_to_utf8((local != NULL && local[0] != L'\0') ? local : L"(none)", g_u8_local, sizeof(g_u8_local));
    wide_to_utf8((remote != NULL && remote[0] != L'\0') ? remote : L"(none)", g_u8_remote, sizeof(g_u8_remote));
    wide_to_utf8((typeName != NULL && typeName[0] != L'\0') ? typeName : L"(unknown)", g_u8_type, sizeof(g_u8_type));
    wide_to_utf8((status != NULL && status[0] != L'\0') ? status : L"Unknown", g_u8_status, sizeof(g_u8_status));
    wide_to_utf8((username != NULL && username[0] != L'\0') ? username : L"(not set)", g_u8_user, sizeof(g_u8_user));

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Connection details\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    Local name  : %s\n", g_u8_local);
    BeaconPrintf(CALLBACK_OUTPUT, "    Remote name : %s\n", g_u8_remote);
    BeaconPrintf(CALLBACK_OUTPUT, "    Type        : %s\n", g_u8_type);
    BeaconPrintf(CALLBACK_OUTPUT, "    Status      : %s\n", g_u8_status);
    BeaconPrintf(CALLBACK_OUTPUT, "    User        : %s\n", g_u8_user);
}

static void net_use_add(LPWSTR deviceName, LPWSTR shareName, LPWSTR password, LPWSTR username, BOOL persist, BOOL requirePrivacy) {
    NETRESOURCEW resource;
    DWORD flags = persist ? CONNECT_UPDATE_PROFILE : CONNECT_TEMPORARY;
    DWORD result;

    if (shareName == NULL || shareName[0] == L'\0') {
        BeaconPrintf(CALLBACK_ERROR, "[-] Share name is required for the add command.\n");
        return;
    }

    if (requirePrivacy) {
        flags |= CONNECT_ENCRYPTED;
    }

    inline_memset(&resource, 0, sizeof(resource));
    resource.dwType = RESOURCETYPE_DISK;
    resource.lpLocalName = deviceName;
    resource.lpRemoteName = shareName;
    resource.lpProvider = NULL;

    result = MPR$WNetAddConnection2W(&resource, password, username, flags);
    if (result == NO_ERROR) {
        char localA[STRING_BUFFER_CHARS];
        char remoteA[STRING_BUFFER_CHARS];

        wide_to_utf8((deviceName != NULL && deviceName[0] != L'\0') ? deviceName : L"(auto)", localA, sizeof(localA));
        wide_to_utf8(shareName, remoteA, sizeof(remoteA));

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Connection added: %s -> %s\n", localA, remoteA);
        if (persist) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Persisted in user profile.\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Temporary connection.\n");
        }
    } else {
        print_windows_error("Failed to add network connection", result);
        if (result == ERROR_INVALID_PARAMETER && requirePrivacy) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CONNECT_ENCRYPTED is not supported on this system.\n");
        }
    }
}

static void net_use_delete(LPWSTR targetName, BOOL persist, BOOL force) {
    DWORD flags = persist ? CONNECT_UPDATE_PROFILE : 0;
    DWORD result;

    if (targetName == NULL || targetName[0] == L'\0') {
        BeaconPrintf(CALLBACK_ERROR, "[-] A target name is required to delete a connection.\n");
        return;
    }

    result = MPR$WNetCancelConnection2W(targetName, flags, force);
    if (result == NO_ERROR) {
        char targetA[STRING_BUFFER_CHARS];
        wide_to_utf8(targetName, targetA, sizeof(targetA));
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Connection removed: %s\n", targetA);
    } else {
        print_windows_error("Failed to remove network connection", result);
    }
}

static void determine_status_text(LPNETRESOURCEW resource, LPWSTR statusBuffer, size_t bufferLen) {
    DWORD infoSize = sizeof(g_winfo_buffer);
    LPWSTR systemPtr = NULL;
    DWORD result;

    copy_wide_string(statusBuffer, bufferLen, L"Unknown");
    inline_memset(g_winfo_buffer, 0, sizeof(g_winfo_buffer));

    result = MPR$WNetGetResourceInformationW(resource, (LPVOID)g_winfo_buffer, &infoSize, &systemPtr);
    if (result == NO_ERROR) {
        copy_wide_string(statusBuffer, bufferLen, L"OK");
    } else if (result == ERROR_BAD_NET_NAME) {
        copy_wide_string(statusBuffer, bufferLen, L"Disconnected");
    } else if (result == ERROR_NO_NETWORK) {
        copy_wide_string(statusBuffer, bufferLen, L"No network");
    } else if (result == ERROR_MORE_DATA) {
        copy_wide_string(statusBuffer, bufferLen, L"Data too large");
    } else {
        copy_wide_string(statusBuffer, bufferLen, L"Unavailable");
    }
}

static void net_use_list(LPWSTR filterName) {
    HANDLE enumHandle = NULL;
    DWORD result;
    DWORD totalPrinted = 0;
    BOOL matchFound = FALSE;
    BOOL filterMode = (filterName != NULL && filterName[0] != L'\0');

    result = MPR$WNetOpenEnumW(RESOURCE_CONNECTED, RESOURCETYPE_ANY, 0, NULL, &enumHandle);
    if (result != NO_ERROR) {
        print_windows_error("WNetOpenEnumW failed", result);
        return;
    }

    if (!filterMode) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerating connected network resources...\n");
    }

    while (TRUE) {
        DWORD entries = 0xFFFFFFFF;
        DWORD bufferSize = sizeof(g_wenum_buffer);

        inline_memset(g_wenum_buffer, 0, sizeof(g_wenum_buffer));
        result = MPR$WNetEnumResourceW(enumHandle, &entries, (LPVOID)g_wenum_buffer, &bufferSize);

        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        } else if (result == ERROR_MORE_DATA) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Enumeration buffer was insufficient for the current resource set.\n");
            break;
        } else if (result != NO_ERROR) {
            print_windows_error("WNetEnumResourceW failed", result);
            break;
        }

        LPNETRESOURCEW resources = (LPNETRESOURCEW)g_wenum_buffer;
        for (DWORD i = 0; i < entries; i++) {
            LPNETRESOURCEW current = &resources[i];
            DWORD userLen = STRING_BUFFER_CHARS;
            DWORD userResult;
            LPCWSTR userTarget = NULL;

            copy_wide_string(g_sc_local, ARRAYSIZE(g_sc_local), current->lpLocalName);
            copy_wide_string(g_sc_remote, ARRAYSIZE(g_sc_remote), current->lpRemoteName);
            copy_wide_string(g_sc_provider, ARRAYSIZE(g_sc_provider), current->lpProvider);
            copy_wide_string(g_sc_type, ARRAYSIZE(g_sc_type), resource_type_name(current->dwType));
            determine_status_text(current, g_sc_status, ARRAYSIZE(g_sc_status));

            inline_memset(g_sc_user, 0, sizeof(g_sc_user));
            userTarget = (g_sc_local[0] != L'\0') ? g_sc_local : g_sc_remote;
            userLen = STRING_BUFFER_CHARS;
            userResult = MPR$WNetGetUserW((userTarget[0] != L'\0') ? userTarget : NULL, g_sc_user, &userLen);
            if (userResult != NO_ERROR) {
                g_sc_user[0] = L'\0';
            }

            if (filterMode) {
                if (!wide_equals_ci(g_sc_local, filterName) && !wide_equals_ci(g_sc_remote, filterName)) {
                    continue;
                }
            }

            matchFound = TRUE;

            if (totalPrinted >= MAX_RESOURCE_OUTPUT) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Output truncated at %lu entries.\n", (unsigned long)MAX_RESOURCE_OUTPUT);
                break;
            }

            totalPrinted++;
            if (filterMode) {
                print_resource_detail(g_sc_local, g_sc_remote, g_sc_type, g_sc_status, g_sc_user);
            } else {
                print_resource_summary(totalPrinted, g_sc_status, g_sc_local, g_sc_remote, g_sc_provider, g_sc_type, g_sc_user);
            }
        }

        if (totalPrinted >= MAX_RESOURCE_OUTPUT) {
            break;
        }
    }

    if (enumHandle != NULL) {
        DWORD closeResult = MPR$WNetCloseEnum(enumHandle);
        if (closeResult != NO_ERROR) {
            print_windows_error("WNetCloseEnum failed", closeResult);
        }
    }

    if (filterMode) {
        if (!matchFound) {
            BeaconPrintf(CALLBACK_ERROR, "[-] No connection matched the supplied name.\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Total resources listed: %lu\n", (unsigned long)totalPrinted);
    }
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    short command = 0;
    LPWSTR shareName = NULL;
    LPWSTR username = NULL;
    LPWSTR password = NULL;
    LPWSTR deviceName = NULL;
    short persist = 0;
    short requirePrivacy = 0;
    short force = 0;

    if (args == NULL || alen == 0 || alen < sizeof(short)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No arguments provided, listing all network connections...\n");
        net_use_list(NULL);
        return;
    }

    BeaconDataParse(&parser, args, (int)alen);
    command = BeaconDataShort(&parser);

    if (command < CMD_ADD || command > CMD_DELETE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid command identifier: %d\n", (int)command);
        BeaconPrintf(CALLBACK_ERROR, "[-] Usage: net_use <1=add | 2=list | 3=delete>\n");
        return;
    }

    switch (command) {
        case CMD_ADD:
            shareName = extract_wide_or_null(&parser);
            username = extract_wide_or_null(&parser);
            password = extract_wide_or_null(&parser);
            deviceName = extract_wide_or_null(&parser);
            persist = BeaconDataShort(&parser);
            requirePrivacy = BeaconDataShort(&parser);
            net_use_add(deviceName, shareName, password, username, (persist != 0), (requirePrivacy != 0));
            break;

        case CMD_LIST:
            deviceName = extract_wide_or_null(&parser);
            net_use_list(deviceName);
            break;

        case CMD_DELETE:
            deviceName = extract_wide_or_null(&parser);
            persist = BeaconDataShort(&parser);
            force = BeaconDataShort(&parser);
            net_use_delete(deviceName, (persist != 0), (force != 0));
            break;

        default:
            BeaconPrintf(CALLBACK_ERROR, "[-] Unknown command identifier: %d\n", (int)command);
            break;
    }
}
