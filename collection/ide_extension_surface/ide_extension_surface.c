#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef DECLSPEC_IMPORT
#ifdef _WIN32
#define DECLSPEC_IMPORT __declspec(dllimport)
#else
#define DECLSPEC_IMPORT
#endif
#endif

#ifndef WINAPI
#ifdef _WIN32
#define WINAPI __stdcall
#else
#define WINAPI
#endif
#endif

#ifndef HANDLE
typedef void *HANDLE;
#endif
#ifndef DWORD
typedef unsigned long DWORD;
#endif
#ifndef BOOL
typedef int BOOL;
#endif
#ifndef LPCWSTR
typedef const unsigned short *LPCWSTR;
#endif
#ifndef LPWSTR
typedef unsigned short *LPWSTR;
#endif
#ifndef LPDWORD
typedef DWORD *LPDWORD;
#endif
#ifndef LPVOID
typedef void *LPVOID;
#endif

#ifndef _WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif

#ifndef STARTUPINFO
typedef struct _STARTUPINFO {
    void *reserved;
} STARTUPINFO;
#endif

#ifndef PROCESS_INFORMATION
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION;
#endif

#include "beacon.h"

#define MAX_PATH_LEN 520
#define MAX_FILE_READ 65535
#define FIELD_SMALL 96
#define FIELD_MEDIUM 160
#define FIELD_LARGE 320

#define SECTION_IDE_EXTENSIONS "[i] IDE Extension Enumeration"

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#endif
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFF)
#endif
#ifndef FILE_ATTRIBUTE_DIRECTORY
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#endif
#ifndef OPEN_EXISTING
#define OPEN_EXISTING 3
#endif
#ifndef GENERIC_READ
#define GENERIC_READ 0x80000000
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ 0x00000001
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE 0x00000002
#endif
#ifndef FILE_SHARE_DELETE
#define FILE_SHARE_DELETE 0x00000004
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x00001000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x00002000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x00008000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif

#ifndef FILETIME_DEFINED
#define FILETIME_DEFINED
typedef struct {
    unsigned long dwLowDateTime;
    unsigned long dwHighDateTime;
} FILETIME;
#endif

typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    unsigned long nFileSizeHigh;
    unsigned long nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    wchar_t cFileName[260];
    wchar_t cAlternateFileName[14];
} WIN32_FIND_DATAW;
typedef WIN32_FIND_DATAW *LPWIN32_FIND_DATAW;

typedef struct {
    int manifests_found;
    int current_root_printed;
} scan_results_t;

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, size_t, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree(LPVOID, size_t, DWORD);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static size_t inline_strlen(const char *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i] != '\0') {
        i++;
    }
    return i;
}

static size_t inline_wcslen(const wchar_t *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i] != L'\0') {
        i++;
    }
    return i;
}

static int build_path(const wchar_t *left, const wchar_t *right, wchar_t *out, size_t out_size) {
    size_t idx = 0;
    size_t i = 0;
    if (!left || !right || !out || out_size == 0) {
        return 0;
    }
    while (left[i] && idx + 1 < out_size) {
        out[idx++] = left[i++];
    }
    i = 0;
    while (right[i] && idx + 1 < out_size) {
        out[idx++] = right[i++];
    }
    if (right[i] != L'\0') {
        out[idx] = L'\0';
        return 0;
    }
    out[idx] = L'\0';
    return 1;
}

static int append_wide_in_place(wchar_t *dst, const wchar_t *suffix, size_t out_size) {
    size_t idx;
    size_t j = 0;
    if (!dst || !suffix || out_size == 0) {
        return 0;
    }
    idx = inline_wcslen(dst);
    while (suffix[j] && idx + 1 < out_size) {
        dst[idx++] = suffix[j++];
    }
    if (suffix[j] != L'\0') {
        if (idx < out_size) {
            dst[idx] = L'\0';
        }
        return 0;
    }
    dst[idx] = L'\0';
    return 1;
}

static int ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

static int ascii_contains_ci(const char *hay, const char *needle) {
    size_t nlen = 0;
    size_t i;
    if (!hay || !needle) {
        return 0;
    }
    while (needle[nlen]) {
        nlen++;
    }
    if (nlen == 0) {
        return 0;
    }
    for (i = 0; hay[i]; i++) {
        size_t j = 0;
        while (hay[i + j] && needle[j] &&
               ascii_tolower((int)hay[i + j]) == ascii_tolower((int)needle[j])) {
            j++;
        }
        if (j == nlen) {
            return 1;
        }
    }
    return 0;
}

static const char *ascii_find(const char *hay, const char *needle) {
    size_t i;
    size_t nlen = inline_strlen(needle);
    if (!hay || !needle || nlen == 0) {
        return NULL;
    }
    for (i = 0; hay[i]; i++) {
        size_t j = 0;
        while (hay[i + j] && needle[j] && hay[i + j] == needle[j]) {
            j++;
        }
        if (j == nlen) {
            return hay + i;
        }
    }
    return NULL;
}

static int path_exists(const wchar_t *path) {
    DWORD attr;
    if (!path) {
        return 0;
    }
    attr = KERNEL32$GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES);
}

static int is_directory(const wchar_t *path) {
    DWORD attr;
    if (!path) {
        return 0;
    }
    attr = KERNEL32$GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    return ((attr & FILE_ATTRIBUTE_DIRECTORY) != 0);
}

static int read_file_text_bounded(LPCWSTR path, DWORD max_bytes, char **out_buf, int *truncated_out) {
    HANDLE hFile;
    DWORD fileSize;
    DWORD toRead;
    DWORD bytesRead = 0;
    char *buffer;

    if (!path || !out_buf || !truncated_out || max_bytes == 0) {
        return 0;
    }

    *out_buf = NULL;
    *truncated_out = 0;

    hFile = KERNEL32$CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_ATTRIBUTES) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }

    toRead = fileSize;
    if (toRead > max_bytes) {
        toRead = max_bytes;
        *truncated_out = 1;
    }

    buffer = (char *)KERNEL32$VirtualAlloc(NULL, (size_t)toRead + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }

    inline_memset(buffer, 0, (size_t)toRead + 1);
    if (!KERNEL32$ReadFile(hFile, buffer, toRead, &bytesRead, NULL)) {
        KERNEL32$CloseHandle(hFile);
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    KERNEL32$CloseHandle(hFile);
    buffer[bytesRead] = '\0';
    *out_buf = buffer;
    return 1;
}

static void skip_json_ws(const char **cursor) {
    while (cursor && *cursor && (**cursor == ' ' || **cursor == '\t' || **cursor == '\r' || **cursor == '\n')) {
        (*cursor)++;
    }
}

static int append_ascii_fragment(char *dst, size_t dst_size, const char *src) {
    size_t idx;
    size_t j = 0;
    if (!dst || !src || dst_size == 0) {
        return 0;
    }
    idx = inline_strlen(dst);
    while (src[j] && idx + 1 < dst_size) {
        dst[idx++] = src[j++];
    }
    dst[idx] = '\0';
    return src[j] == '\0';
}

static int extract_json_string_value(const char *json, const char *key, char *out, size_t out_size) {
    const char *match;
    size_t i = 0;
    if (!json || !key || !out || out_size == 0) {
        return 0;
    }
    match = ascii_find(json, key);
    if (!match) {
        out[0] = '\0';
        return 0;
    }
    match += inline_strlen(key);
    while (*match && *match != ':') {
        match++;
    }
    if (*match != ':') {
        out[0] = '\0';
        return 0;
    }
    match++;
    skip_json_ws(&match);
    if (*match != '"') {
        out[0] = '\0';
        return 0;
    }
    match++;
    while (*match && i + 1 < out_size) {
        if (*match == '\\') {
            match++;
            if (!*match) {
                break;
            }
            if (*match == 'n' || *match == 'r' || *match == 't') {
                out[i++] = ' ';
                match++;
                continue;
            }
        }
        if (*match == '"') {
            break;
        }
        out[i++] = *match++;
    }
    out[i] = '\0';
    return i > 0;
}

static int summarize_json_string_array(const char *json, const char *key, char *out, size_t out_size, int max_entries) {
    const char *match;
    int entries = 0;
    int truncated = 0;

    if (!json || !key || !out || out_size == 0 || max_entries <= 0) {
        return 0;
    }

    out[0] = '\0';
    match = ascii_find(json, key);
    if (!match) {
        return 0;
    }
    match += inline_strlen(key);
    while (*match && *match != ':') {
        match++;
    }
    if (*match != ':') {
        return 0;
    }
    match++;
    skip_json_ws(&match);
    if (*match != '[') {
        return 0;
    }
    match++;

    while (*match) {
        char item[FIELD_SMALL];
        size_t item_len = 0;

        skip_json_ws(&match);
        if (*match == ']') {
            break;
        }
        if (*match != '"') {
            match++;
            continue;
        }
        match++;
        inline_memset(item, 0, sizeof(item));
        while (*match && *match != '"' && item_len + 1 < sizeof(item)) {
            if (*match == '\\') {
                match++;
                if (!*match) {
                    break;
                }
            }
            item[item_len++] = *match++;
        }
        item[item_len] = '\0';
        while (*match && *match != '"' && *match != ',' && *match != ']') {
            match++;
        }
        if (*match == '"') {
            match++;
        }

        if (entries < max_entries) {
            if (entries > 0) {
                if (!append_ascii_fragment(out, out_size, ", ")) {
                    truncated = 1;
                    break;
                }
            }
            if (!append_ascii_fragment(out, out_size, item)) {
                truncated = 1;
                break;
            }
        } else {
            truncated = 1;
        }
        entries++;

        while (*match && *match != ',' && *match != ']') {
            match++;
        }
        if (*match == ',') {
            match++;
        }
        if (*match == ']') {
            break;
        }
    }

    if (entries == 0) {
        out[0] = '\0';
        return 0;
    }
    if (truncated || entries > max_entries) {
        append_ascii_fragment(out, out_size, ", ... (truncated)");
    }
    return 1;
}

static int summarize_json_scalar_or_array(const char *json, const char *key, char *out, size_t out_size, int max_entries) {
    const char *match;
    if (!json || !key || !out || out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    if (summarize_json_string_array(json, key, out, out_size, max_entries)) {
        return 1;
    }

    match = ascii_find(json, key);
    if (!match) {
        return 0;
    }
    match += inline_strlen(key);
    while (*match && *match != ':') {
        match++;
    }
    if (*match != ':') {
        return 0;
    }
    match++;
    skip_json_ws(&match);

    if (*match == '"') {
        return extract_json_string_value(json, key, out, out_size);
    }
    if (*match == '{') {
        return append_ascii_fragment(out, out_size, "{...}");
    }
    if (*match == '[') {
        return append_ascii_fragment(out, out_size, "[...]");
    }
    while (*match && *match != ',' && *match != '}' && inline_strlen(out) + 1 < out_size) {
        char c[2];
        c[0] = *match;
        c[1] = '\0';
        append_ascii_fragment(out, out_size, c);
        match++;
    }
    return out[0] != '\0';
}

static int append_capability_label(char *out, size_t out_size, const char *label) {
    if (!out || !label || out_size == 0) {
        return 0;
    }
    if (out[0] != '\0') {
        if (!append_ascii_fragment(out, out_size, ", ")) {
            return 0;
        }
    }
    return append_ascii_fragment(out, out_size, label);
}

static int append_capability_value(char *out, size_t out_size, const char *prefix, const char *value) {
    char label[FIELD_LARGE];
    if (!value || value[0] == '\0') {
        return 0;
    }
    inline_memset(label, 0, sizeof(label));
    append_ascii_fragment(label, sizeof(label), prefix);
    append_ascii_fragment(label, sizeof(label), value);
    return append_capability_label(out, out_size, label);
}

static void summarize_capabilities(const char *json, char *out, size_t out_size) {
    char temp[FIELD_MEDIUM];
    int has_contributes = 0;

    if (!json || !out || out_size == 0) {
        return;
    }
    out[0] = '\0';

    inline_memset(temp, 0, sizeof(temp));
    if (summarize_json_scalar_or_array(json, "\"permissions\"", temp, sizeof(temp), 3)) {
        append_capability_value(out, out_size, "permissions=", temp);
    }

    inline_memset(temp, 0, sizeof(temp));
    if (summarize_json_scalar_or_array(json, "\"enabledApiProposals\"", temp, sizeof(temp), 3)) {
        append_capability_value(out, out_size, "apiProposals=", temp);
    }

    inline_memset(temp, 0, sizeof(temp));
    if (summarize_json_scalar_or_array(json, "\"extensionKind\"", temp, sizeof(temp), 3)) {
        append_capability_value(out, out_size, "extensionKind=", temp);
    }

    if (ascii_find(json, "\"main\"")) {
        append_capability_label(out, out_size, "main");
    }
    if (ascii_find(json, "\"browser\"")) {
        append_capability_label(out, out_size, "browser");
    }

    has_contributes = ascii_find(json, "\"contributes\"") != NULL;
    if (has_contributes && ascii_find(json, "\"commands\"")) {
        append_capability_label(out, out_size, "commands");
    }
    if (has_contributes && ascii_find(json, "\"authentication\"")) {
        append_capability_label(out, out_size, "authentication");
    }
    if (has_contributes && ascii_find(json, "\"walkthroughs\"")) {
        append_capability_label(out, out_size, "walkthroughs");
    }
    if (has_contributes && ascii_find(json, "\"taskDefinitions\"")) {
        append_capability_label(out, out_size, "taskDefinitions");
    }
    if (has_contributes && ascii_find(json, "\"debuggers\"")) {
        append_capability_label(out, out_size, "debuggers");
    }
    if (has_contributes && (ascii_find(json, "\"terminalProfiles\"") || ascii_find(json, "\"terminal\""))) {
        append_capability_label(out, out_size, "terminal");
    }
    if (has_contributes && ascii_find(json, "\"chatParticipants\"")) {
        append_capability_label(out, out_size, "chatParticipants");
    }
    if (has_contributes && ascii_find(json, "\"languageModels\"")) {
        append_capability_label(out, out_size, "languageModels");
    }
    if (ascii_contains_ci(json, "\"mcp\"") || ascii_contains_ci(json, "modelcontextprotocol")) {
        append_capability_label(out, out_size, "mcp-adjacent");
    }
}

static int extract_toml_string_value(const char *toml, const char *key, char *out, size_t out_size) {
    char pattern[FIELD_SMALL];
    const char *match;
    char quote;
    size_t i = 0;

    if (!toml || !key || !out || out_size == 0) {
        return 0;
    }

    inline_memset(pattern, 0, sizeof(pattern));
    if (!append_ascii_fragment(pattern, sizeof(pattern), key) ||
        !append_ascii_fragment(pattern, sizeof(pattern), " = \"")) {
        out[0] = '\0';
        return 0;
    }

    match = ascii_find(toml, pattern);
    if (!match) {
        inline_memset(pattern, 0, sizeof(pattern));
        if (!append_ascii_fragment(pattern, sizeof(pattern), key) ||
            !append_ascii_fragment(pattern, sizeof(pattern), " = '")) {
            out[0] = '\0';
            return 0;
        }
        match = ascii_find(toml, pattern);
        if (!match) {
            out[0] = '\0';
            return 0;
        }
        quote = '\'';
    } else {
        quote = '"';
    }

    match += inline_strlen(pattern);
    while (*match && i + 1 < out_size) {
        if (*match == quote) {
            break;
        }
        out[i++] = *match++;
    }
    out[i] = '\0';
    return i > 0;
}

static void summarize_zed_capabilities(const char *toml, char *out, size_t out_size) {
    if (!toml || !out || out_size == 0) {
        return;
    }
    out[0] = '\0';

    if (ascii_find(toml, "languages/") || ascii_find(toml, "[languages]")) {
        append_capability_label(out, out_size, "languages");
    }
    if (ascii_find(toml, "themes/") || ascii_find(toml, "[themes]")) {
        append_capability_label(out, out_size, "themes");
    }
    if (ascii_find(toml, "snippets/") || ascii_find(toml, "[snippets]")) {
        append_capability_label(out, out_size, "snippets");
    }
    if (ascii_find(toml, "[debuggers]") || ascii_find(toml, "debuggers/")) {
        append_capability_label(out, out_size, "debuggers");
    }
    if (ascii_find(toml, "Cargo.toml") || ascii_find(toml, "src/lib.rs")) {
        append_capability_label(out, out_size, "wasm");
    }
    if (ascii_contains_ci(toml, "mcp") || ascii_contains_ci(toml, "modelcontextprotocol")) {
        append_capability_label(out, out_size, "mcp-adjacent");
    }
}

static void build_extension_id(const char *publisher, const char *name, char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (publisher && publisher[0] != '\0' && name && name[0] != '\0') {
        append_ascii_fragment(out, out_size, publisher);
        append_ascii_fragment(out, out_size, ".");
        append_ascii_fragment(out, out_size, name);
        return;
    }
    if (publisher && publisher[0] != '\0') {
        append_ascii_fragment(out, out_size, publisher);
        return;
    }
    if (name && name[0] != '\0') {
        append_ascii_fragment(out, out_size, name);
    }
}

static void print_root_header_if_needed(scan_results_t *results, const wchar_t *editor_label, const wchar_t *resolved_root) {
    if (!results || !editor_label || !resolved_root) {
        return;
    }
    if (results->current_root_printed) {
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n[i] %S: %S\n", editor_label, resolved_root);
    results->current_root_printed = 1;
}

static void report_manifest(const wchar_t *editor_label, const wchar_t *resolved_root, const wchar_t *manifest_path, const char *json, int was_truncated, scan_results_t *results) {
    char publisher[FIELD_SMALL];
    char name[FIELD_SMALL];
    char display_name[FIELD_MEDIUM];
    char version[FIELD_SMALL];
    char extension_id[FIELD_MEDIUM];
    char activation[FIELD_LARGE];
    char capabilities[FIELD_LARGE];

    if (!editor_label || !resolved_root || !manifest_path || !json || !results) {
        return;
    }

    inline_memset(publisher, 0, sizeof(publisher));
    inline_memset(name, 0, sizeof(name));
    inline_memset(display_name, 0, sizeof(display_name));
    inline_memset(version, 0, sizeof(version));
    inline_memset(extension_id, 0, sizeof(extension_id));
    inline_memset(activation, 0, sizeof(activation));
    inline_memset(capabilities, 0, sizeof(capabilities));

    extract_json_string_value(json, "\"publisher\"", publisher, sizeof(publisher));
    extract_json_string_value(json, "\"name\"", name, sizeof(name));
    extract_json_string_value(json, "\"displayName\"", display_name, sizeof(display_name));
    extract_json_string_value(json, "\"version\"", version, sizeof(version));
    summarize_json_string_array(json, "\"activationEvents\"", activation, sizeof(activation), 3);
    summarize_capabilities(json, capabilities, sizeof(capabilities));
    build_extension_id(publisher, name, extension_id, sizeof(extension_id));

    print_root_header_if_needed(results, editor_label, resolved_root);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Manifest: %S\n", manifest_path);
    if (extension_id[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   ID: %s\n", extension_id);
    }
    if (display_name[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Display Name: %s\n", display_name);
    }
    if (version[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Version: %s\n", version);
    }
    if (publisher[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Publisher: %s\n", publisher);
    }
    if (activation[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Activation: %s\n", activation);
    }
    if (capabilities[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Capabilities: %s\n", capabilities);
    }
    if (was_truncated) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Note: package.json truncated at %d bytes\n", MAX_FILE_READ);
    }

    results->manifests_found++;
}

static void report_zed_manifest(const wchar_t *editor_label, const wchar_t *resolved_root, const wchar_t *manifest_path, const char *toml, int was_truncated, scan_results_t *results) {
    char display_name[FIELD_MEDIUM];
    char version[FIELD_SMALL];
    char extension_id[FIELD_MEDIUM];
    char description[FIELD_LARGE];
    char capabilities[FIELD_LARGE];

    if (!editor_label || !resolved_root || !manifest_path || !toml || !results) {
        return;
    }

    inline_memset(display_name, 0, sizeof(display_name));
    inline_memset(version, 0, sizeof(version));
    inline_memset(extension_id, 0, sizeof(extension_id));
    inline_memset(description, 0, sizeof(description));
    inline_memset(capabilities, 0, sizeof(capabilities));

    extract_toml_string_value(toml, "id", extension_id, sizeof(extension_id));
    extract_toml_string_value(toml, "name", display_name, sizeof(display_name));
    extract_toml_string_value(toml, "version", version, sizeof(version));
    extract_toml_string_value(toml, "description", description, sizeof(description));
    summarize_zed_capabilities(toml, capabilities, sizeof(capabilities));

    print_root_header_if_needed(results, editor_label, resolved_root);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Manifest: %S\n", manifest_path);
    if (extension_id[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   ID: %s\n", extension_id);
    }
    if (display_name[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Display Name: %s\n", display_name);
    }
    if (version[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Version: %s\n", version);
    }
    if (description[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Description: %s\n", description);
    }
    if (capabilities[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Capabilities: %s\n", capabilities);
    }
    if (was_truncated) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Note: extension.toml truncated at %d bytes\n", MAX_FILE_READ);
    }

    results->manifests_found++;
}

static void scan_extension_root(const wchar_t *editor_label, const wchar_t *pattern, const wchar_t *manifest_name, int is_toml, scan_results_t *results) {
    wchar_t root[MAX_PATH_LEN];
    wchar_t search[MAX_PATH_LEN];
    wchar_t child_dir[MAX_PATH_LEN];
    wchar_t manifest_leaf[MAX_PATH_LEN];
    wchar_t manifest_path[MAX_PATH_LEN];
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD needed;

    if (!editor_label || !pattern || !manifest_name || !results) {
        return;
    }

    inline_memset(root, 0, sizeof(root));
    needed = KERNEL32$ExpandEnvironmentStringsW(pattern, root, MAX_PATH_LEN);
    if (needed == 0 || needed > MAX_PATH_LEN || !is_directory(root)) {
        return;
    }

    inline_memset(search, 0, sizeof(search));
    if (!build_path(root, L"\\*", search, MAX_PATH_LEN)) {
        return;
    }

    inline_memset(&fd, 0, sizeof(fd));
    hFind = KERNEL32$FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    results->current_root_printed = 0;
    do {
        char *buffer = NULL;
        int was_truncated = 0;

        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }
        if (fd.cFileName[0] == L'.') {
            continue;
        }

        inline_memset(child_dir, 0, sizeof(child_dir));
        inline_memset(manifest_leaf, 0, sizeof(manifest_leaf));
        inline_memset(manifest_path, 0, sizeof(manifest_path));
        if (!build_path(root, L"\\", child_dir, MAX_PATH_LEN) ||
            !append_wide_in_place(child_dir, fd.cFileName, MAX_PATH_LEN) ||
            !build_path(L"\\", manifest_name, manifest_leaf, MAX_PATH_LEN) ||
            !build_path(child_dir, manifest_leaf, manifest_path, MAX_PATH_LEN)) {
            continue;
        }
        if (!path_exists(manifest_path)) {
            continue;
        }
        if (!read_file_text_bounded(manifest_path, MAX_FILE_READ, &buffer, &was_truncated)) {
            continue;
        }

        if (is_toml) {
            report_zed_manifest(editor_label, root, manifest_path, buffer, was_truncated, results);
        } else {
            report_manifest(editor_label, root, manifest_path, buffer, was_truncated, results);
        }
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    scan_results_t results;

    BeaconDataParse(&parser, args, (int)alen);
    inline_memset(&results, 0, sizeof(results));

    BeaconPrintf(CALLBACK_OUTPUT, SECTION_IDE_EXTENSIONS ":\n");

    scan_extension_root(L"VS Code", L"%USERPROFILE%\\.vscode\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"VS Code Insiders", L"%USERPROFILE%\\.vscode-insiders\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"VS Code OSS", L"%USERPROFILE%\\.vscode-oss\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"Cursor", L"%USERPROFILE%\\.cursor\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"Windsurf", L"%USERPROFILE%\\.windsurf\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"Windsurf (Codeium root)", L"%USERPROFILE%\\.codeium\\windsurf\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"Zed", L"%LOCALAPPDATA%\\Zed\\extensions\\installed", L"extension.toml", 1, &results);
    scan_extension_root(L"VS Code Server", L"%USERPROFILE%\\.vscode-server\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"Cursor Server", L"%USERPROFILE%\\.cursor-server\\extensions", L"package.json", 0, &results);
    scan_extension_root(L"VS Code Remote", L"%USERPROFILE%\\.vscode-remote\\extensions", L"package.json", 0, &results);

    if (results.manifests_found == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    }
}
