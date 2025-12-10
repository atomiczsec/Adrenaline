#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

typedef HANDLE EVT_HANDLE;

#define MY_EVT_RENDER_EVENT_XML        0x00000001
#define EvtRenderEventValues           0x00000000
#define EvtRenderContextSystem         1
#define MY_EVT_QUERY_CHANNEL_PATH      0x00000001
#define MY_EVT_QUERY_REVERSE_DIRECTION 0x00000200
#define MY_WAIT_TIMEOUT                0x00000102
#define MY_ERROR_NO_MORE_ITEMS         0x00000103
#define MY_ERROR_INSUFFICIENT_BUFFER   122

#define MY_EVT_VT_NULL                 0x0001
#define MY_EVT_VT_BOOL                 0x000B
#define MY_EVT_VT_I2                   0x0002
#define MY_EVT_VT_I4                   0x0003
#define MY_EVT_VT_I8                   0x0014
#define MY_EVT_VT_UINT8                0x0011
#define MY_EVT_VT_STRING               0x0008
#define MY_EVT_VT_ARRAY                0x2000
#define MY_EVT_VT_NULL_ARRAY_MASK      0x2001


typedef struct {
    union {
        BOOL        BooleanVal;
        INT8        SByteVal;
        UINT8       ByteVal;
        INT16       Int16Val;
        UINT16      UInt16Val;
        INT32       Int32Val;
        UINT32      UInt32Val;
        INT64       Int64Val;
        UINT64      UInt64Val;
        float       SingleVal;
        double      DoubleVal;
        FILETIME    FileTimeVal;
        SYSTEMTIME  SysTimeVal;
        GUID        GuidVal;
        LPCWSTR     StringVal;
        PBYTE       BinaryVal;
        PSID        SidVal;
        size_t      SizeVal;
        BOOL        *BooleanArr;
        INT8        *SByteArr;
        UINT8       *ByteArr;
        INT16       *Int16Arr;
        UINT16      *UInt16Arr;
        INT32       *Int32Arr;
        UINT32      *UInt32Arr;
        INT64       *Int64Arr;
        UINT64      *UInt64Arr;
        float       *SingleArr;
        double      *DoubleArr;
        FILETIME    *FileTimeArr;
        SYSTEMTIME  *SysTimeArr;
        GUID        *GuidArr;
        LPCWSTR     *StringArr;
        PBYTE       *BinaryArr;
        PSID        *SidArr;
        size_t      *SizeArr;
    };
    DWORD Count;
    DWORD Type;
} EVT_VARIANT, *PEVT_VARIANT;

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

typedef EVT_HANDLE (WINAPI *pfnEvtQuery)(
    EVT_HANDLE Session,
    LPCWSTR    Path,
    LPCWSTR    Query,
    DWORD      Flags
);

typedef BOOL (WINAPI *pfnEvtNext)(
    EVT_HANDLE ResultSet,
    DWORD      EventArraySize,
    EVT_HANDLE *EventArray,
    DWORD      Timeout,
    DWORD      Flags,
    PDWORD     Returned
);

typedef BOOL (WINAPI *pfnEvtRender)(
    EVT_HANDLE Context,
    EVT_HANDLE Fragment,
    DWORD      Flags,
    DWORD      BufferSize,
    PVOID      Buffer,
    PDWORD     BufferUsed,
    PDWORD     PropertyCount
);

typedef BOOL (WINAPI *pfnEvtClose)(
    EVT_HANDLE Object
);

typedef EVT_HANDLE (WINAPI *pfnEvtCreateRenderContext)(
    DWORD      ValuePathsCount,
    LPCWSTR    *ValuePaths,
    DWORD      Flags
);

typedef struct {
    pfnEvtQuery            EvtQuery;
    pfnEvtNext             EvtNext;
    pfnEvtRender           EvtRender;
    pfnEvtClose            EvtClose;
    pfnEvtCreateRenderContext EvtCreateRenderContext;
} EvtApis;

static void *inline_memset(void *dest, int val, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)val;
    }
    return dest;
}

static __attribute__((unused)) void *inline_memcpy(void *dest, const void *src, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (count--) {
        *d++ = *s++;
    }
    return dest;
}

static int inline_strlen(const char *s) {
    int len = 0;
    if (!s) {
        return 0;
    }
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

static int wide_to_ascii(const wchar_t *src, char *dst, int dst_size) {
    int i = 0;
    if (!src || !dst || dst_size <= 0) {
        return 0;
    }
    dst_size -= 1;
    while (src[i] != L'\0' && i < dst_size) {
        wchar_t c = src[i];
        if (c <= 0x7f) {
            dst[i] = (char)c;
        } else {
            dst[i] = '?';
        }
        i++;
    }
    dst[i] = '\0';
    return i;
}

static int resolve_wevtapi_functions(EvtApis *apis) {
    HMODULE hMod;
    
    if (!apis) {
        return 0;
    }
    
    apis->EvtQuery = NULL;
    apis->EvtNext = NULL;
    apis->EvtRender = NULL;
    apis->EvtClose = NULL;
    apis->EvtCreateRenderContext = NULL;
    
    hMod = KERNEL32$GetModuleHandleW(L"wevtapi.dll");
    if (!hMod) {
        hMod = KERNEL32$LoadLibraryW(L"wevtapi.dll");
    }
    if (!hMod) {
        return 0;
    }
    
    apis->EvtQuery = (pfnEvtQuery)(void*)KERNEL32$GetProcAddress(hMod, "EvtQuery");
    if (!apis->EvtQuery) {
        return 0;
    }

    apis->EvtNext = (pfnEvtNext)(void*)KERNEL32$GetProcAddress(hMod, "EvtNext");
    if (!apis->EvtNext) {
        return 0;
    }

    apis->EvtRender = (pfnEvtRender)(void*)KERNEL32$GetProcAddress(hMod, "EvtRender");
    if (!apis->EvtRender) {
        return 0;
    }

    apis->EvtClose = (pfnEvtClose)(void*)KERNEL32$GetProcAddress(hMod, "EvtClose");
    if (!apis->EvtClose) {
        return 0;
    }

    apis->EvtCreateRenderContext = (pfnEvtCreateRenderContext)(void*)KERNEL32$GetProcAddress(hMod, "EvtCreateRenderContext");
    if (!apis->EvtCreateRenderContext) {
        return 0;
    }

    return 1;
}

static const wchar_t *wcsistr(const wchar_t *haystack, const wchar_t *needle) {
    const wchar_t *h, *n, *start;
    wchar_t hc, nc;
    if (!haystack || !needle || !*needle) {
        return NULL;
    }
    for (start = haystack; *start; start++) {
        h = start;
        n = needle;
        while (*h && *n) {
            hc = *h;
            nc = *n;
            if (hc >= L'a' && hc <= L'z') {
                hc = hc - L'a' + L'A';
            }
            if (nc >= L'a' && nc <= L'z') {
                nc = nc - L'a' + L'A';
            }
            if (hc != nc) {
                break;
            }
            h++;
            n++;
        }
        if (!*n) {
            return start;
        }
    }
    return NULL;
}

static int inline_wcsicmp(const wchar_t *s1, const wchar_t *s2) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    while (*s1 && *s2) {
        wchar_t c1 = *s1;
        wchar_t c2 = *s2;
        if (c1 >= L'a' && c1 <= L'z') c1 = c1 - L'a' + L'A';
        if (c2 >= L'a' && c2 <= L'z') c2 = c2 - L'a' + L'A';
        if (c1 != c2) return (c1 < c2) ? -1 : 1;
        s1++;
        s2++;
    }
    if (*s1) return 1;
    if (*s2) return -1;
    return 0;
}

static int inline_wcscmp(const wchar_t *s1, const wchar_t *s2) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    while (*s1 && *s2) {
        if (*s1 != *s2) return (*s1 < *s2) ? -1 : 1;
        s1++;
        s2++;
    }
    if (*s1) return 1;
    if (*s2) return -1;
    return 0;
}

static size_t inline_wcslen(const wchar_t *s) {
    size_t len = 0;
    if (!s) return 0;
    while (s[len]) len++;
    return len;
}

static void enumerate_logon_events(EvtApis *apis) {
#define MAX_EVENTS     32
#define EVT_BATCH_SIZE 4
#define FIELD_BUF_LEN  64
#define MAX_BUFFER_SIZE 16384

    EVT_HANDLE hQuery = NULL;
    EVT_HANDLE hContext = NULL;
    EVT_HANDLE events[EVT_BATCH_SIZE];
    DWORD returned = 0;
    DWORD total_events = 0;
    DWORD filtered_events = 0;
    DWORD buffer_used = 0;
    DWORD prop_count = 0;
    int i = 0;
    UINT32 eventId = 0;

    if (!apis || !apis->EvtQuery) {
        return;
    }

    hContext = NULL;

    inline_memset(events, 0, sizeof(events));

    KERNEL32$GetLastError();
    
    hQuery = apis->EvtQuery(
        (EVT_HANDLE)NULL,
        L"Security",
        L"*[System[(EventID=4624 or EventID=4625 or EventID=4672)]]",
        MY_EVT_QUERY_CHANNEL_PATH | MY_EVT_QUERY_REVERSE_DIRECTION
    );

    if (!hQuery) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] EvtQuery failed (error: %lu / 0x%lx)\n",
                     (unsigned long)err, (unsigned long)err);
        if (err == 5) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Access denied - try running as Administrator/SYSTEM\n");
        }
        if (hContext) {
            apis->EvtClose(hContext);
        }
        return;
    }

    while (total_events < MAX_EVENTS) {
        inline_memset(events, 0, sizeof(events));
        returned = 0;

        if (!apis->EvtNext(
                hQuery,
                EVT_BATCH_SIZE,
                events,
                1000,
                0,
                &returned
            )) {
            DWORD err = KERNEL32$GetLastError();
            if (err == MY_WAIT_TIMEOUT || err == MY_ERROR_NO_MORE_ITEMS) {
                break;
            }
            BeaconPrintf(CALLBACK_ERROR,
                         "[-] EvtNext failed (error: %lu)\n",
                         (unsigned long)err);
            break;
        }

        for (i = 0; i < (int)returned && total_events < MAX_EVENTS; i++) {
            #define XML_BUF_SIZE_BYTES 8192
            #define XML_BUF_SIZE_CHARS (XML_BUF_SIZE_BYTES / sizeof(wchar_t))
            wchar_t xmlBuffer[XML_BUF_SIZE_CHARS];

            inline_memset(xmlBuffer, 0, sizeof(xmlBuffer));
            buffer_used = 0;
            prop_count = 0;

            if (!apis->EvtRender(
                    NULL,
                    events[i],
                    MY_EVT_RENDER_EVENT_XML,
                    0,
                    NULL,
                    &buffer_used,
                    &prop_count)) {
                DWORD err = KERNEL32$GetLastError();
                if (err != MY_ERROR_INSUFFICIENT_BUFFER) {
                    BeaconPrintf(CALLBACK_ERROR, "[-] EvtRender (XML size query) failed (error: %lu)\n", (unsigned long)err);
                    goto next_event;
                }
            }

            if (buffer_used > XML_BUF_SIZE_BYTES) {
                goto next_event;
            }

            if (!apis->EvtRender(
                    NULL,
                    events[i],
                    MY_EVT_RENDER_EVENT_XML,
                    XML_BUF_SIZE_BYTES,
                    xmlBuffer,
                    &buffer_used,
                    &prop_count)) {
                DWORD err = KERNEL32$GetLastError();
                BeaconPrintf(CALLBACK_ERROR, "[-] EvtRender (XML) failed (error: %lu)\n", (unsigned long)err);
                goto next_event;
            }

            DWORD chars_used = buffer_used / sizeof(wchar_t);
            if (chars_used < XML_BUF_SIZE_CHARS) {
                xmlBuffer[chars_used] = L'\0';
            } else {
                xmlBuffer[XML_BUF_SIZE_CHARS - 1] = L'\0';
            }

            const wchar_t *p;
            const wchar_t *buf_end = xmlBuffer + XML_BUF_SIZE_CHARS;

            wchar_t extractedUser[128] = {0};
            wchar_t extractedWs[128] = {0};
            wchar_t extractedIp[128] = {0};
            wchar_t extractedEventId[16] = {0};

#define EXTRACT(tagstart, dest) \
            if ((p = wcsistr(xmlBuffer, tagstart)) != NULL) { \
                if (p >= xmlBuffer && p < buf_end) { \
                    while (p < buf_end && *p && *p != L'>') p++; \
                    if (p < buf_end && *p == L'>') { \
                        p++; \
                        int k = 0; \
                        int dest_size = (int)(sizeof(dest)/sizeof(wchar_t)); \
                        while (p < buf_end && (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n')) p++; \
                        while (p + k < buf_end && p[k] && p[k] != L'<' && k < dest_size-1) { \
                            dest[k] = p[k]; \
                            k++; \
                        } \
                        dest[k] = L'\0'; \
                    } \
                } \
            }

            if ((p = wcsistr(xmlBuffer, L"<EventID")) != NULL) {
                if (p >= xmlBuffer && p < buf_end) {
                    while (p < buf_end && *p && *p != L'>') p++;
                    if (p < buf_end && *p == L'>') {
                        p++;
                        int k = 0;
                        int dest_size = (int)(sizeof(extractedEventId)/sizeof(wchar_t));
                        while (p < buf_end && (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n')) p++;
                        while (p + k < buf_end && p[k] >= L'0' && p[k] <= L'9' && k < dest_size-1) {
                            extractedEventId[k] = p[k];
                            k++;
                        }
                        extractedEventId[k] = L'\0';
                    }
                }
            }
            EXTRACT(L"<Data Name=\"TargetUserName", extractedUser);
            if (extractedUser[0] == L'\0') {
                EXTRACT(L"<Data Name='TargetUserName", extractedUser);
            }
            
            EXTRACT(L"<Data Name=\"WorkstationName", extractedWs);
            if (extractedWs[0] == L'\0') {
                EXTRACT(L"<Data Name='WorkstationName", extractedWs);
            }
            
            EXTRACT(L"<Data Name=\"IpAddress", extractedIp);
            if (extractedIp[0] == L'\0') {
                EXTRACT(L"<Data Name='IpAddress", extractedIp);
            }

            if (extractedUser[0] == L'\0') {
                EXTRACT(L"<Data Name=\"SubjectUserName", extractedUser);
                if (extractedUser[0] == L'\0') {
                    EXTRACT(L"<Data Name='SubjectUserName", extractedUser);
                }
            }

            eventId = 0;
            if (extractedEventId[0] != L'\0') {
                int k = 0;
                while (extractedEventId[k] >= L'0' && extractedEventId[k] <= L'9') {
                    eventId = eventId * 10 + (extractedEventId[k] - L'0');
                    k++;
                }
            }

            int is_noise = 0;

            if (wcsistr(extractedUser, L"NT AUTHORITY\\") ||
                wcsistr(extractedUser, L"NT VIRTUAL MACHINE\\") ||
                wcsistr(extractedUser, L"WINDOWS MANAGER\\") ||
                wcsistr(extractedUser, L"DWM-") ||
                wcsistr(extractedUser, L"UMFD-") ||
                wcsistr(extractedUser, L"SYSTEM") ||
                inline_wcsicmp(extractedUser, L"SYSTEM") == 0 ||
                inline_wcsicmp(extractedUser, L"LOCAL SERVICE") == 0 ||
                inline_wcsicmp(extractedUser, L"NETWORK SERVICE") == 0) {
                is_noise = 1;
            }

            if (wcsistr(extractedUser, L"$") && inline_wcslen(extractedUser) > 1) {
                is_noise = 1;
            }

            if (extractedWs[0] == L'\0' && extractedIp[0] == L'\0') {
                is_noise = 1;
            }

            if (is_noise) {
                filtered_events++;
                goto next_event;
            }

            char user_a[128], ws_a[128], ip_a[128];
            wide_to_ascii(extractedUser, user_a, sizeof(user_a));
            wide_to_ascii(extractedWs,   ws_a,   sizeof(ws_a));
            wide_to_ascii(extractedIp,   ip_a,   sizeof(ip_a));

            const char *source = "(local)";
            if (extractedWs[0] && inline_wcscmp(extractedWs, L"-") != 0)
                source = ws_a;
            else if (extractedIp[0] && inline_wcscmp(extractedIp, L"-") != 0)
                source = ip_a;

            int is_remote = 0;
            if ((extractedWs[0] && inline_wcscmp(extractedWs, L"-") != 0) ||
                (extractedIp[0] && inline_wcscmp(extractedIp, L"-") != 0)) {
                is_remote = 1;
            }

            if (is_remote) {
                BeaconPrintf(CALLBACK_OUTPUT, "[R] %s from %s (IP: %s)\n", 
                    user_a[0] ? user_a : "(unknown)",
                    extractedWs[0] && inline_wcscmp(extractedWs, L"-") != 0 ? ws_a : "(none)",
                    extractedIp[0] && inline_wcscmp(extractedIp, L"-") != 0 ? ip_a : "(none)");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[L] user: %-20s -> %s\n",
                    user_a[0] ? user_a : "(unknown)",
                    source);
            } 

next_event:
            if (events[i]) {
                apis->EvtClose(events[i]);
                events[i] = (EVT_HANDLE)NULL;
            }
            total_events++;
        }

        if (returned == 0) {
            break;
        }
    }

    if (hQuery) {
        apis->EvtClose(hQuery);
    }
    if (hContext) {
        apis->EvtClose(hContext);
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[i] Processed %lu events (max %d).\n",
                 (unsigned long)total_events,
                 MAX_EVENTS);
    if (filtered_events > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[i] Filtered %lu noise/service events.\n",
                     (unsigned long)filtered_events);
    }
}

void go(char *args, int length) {
    EvtApis apis;
    
    (void)args;
    (void)length;

    if (!resolve_wevtapi_functions(&apis)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve wevtapi.dll functions\n");
        return;
    }

    enumerate_logon_events(&apis);
}

