#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include "beacon.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#ifndef CP_ACP
#define CP_ACP 0
#endif

#define MAX_WIDE 256
#define MAX_OUTPUT_CHUNK 4096
#define MAX_ENUM_RULES 200
#define MAX_RULE_NAME_CHARS 160
#define MAX_RULE_PORT_CHARS 96
#define MAX_RULE_KEY_CHARS 320

#ifndef STDMETHODCALLTYPE
#define STDMETHODCALLTYPE __stdcall
#endif
#ifndef CONST_VTBL
#define CONST_VTBL
#endif

#ifndef __IUnknown_INTERFACE_DEFINED__
typedef struct IUnknown IUnknown;
typedef struct IUnknownVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IUnknown *This, REFIID riid, void **ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(IUnknown *This);
    ULONG (STDMETHODCALLTYPE *Release)(IUnknown *This);
} IUnknownVtbl;

struct IUnknown {
    CONST_VTBL struct IUnknownVtbl *lpVtbl;
};
#define __IUnknown_INTERFACE_DEFINED__
#endif

#ifndef LPUNKNOWN
typedef IUnknown *LPUNKNOWN;
#endif

#ifndef OLECHAR
typedef wchar_t OLECHAR;
#endif

#ifndef BSTR
typedef OLECHAR *BSTR;
#endif

#ifndef VARIANT_BOOL
typedef short VARIANT_BOOL;
#ifndef VARIANT_TRUE
#define VARIANT_TRUE ((VARIANT_BOOL)-1)
#endif
#ifndef VARIANT_FALSE
#define VARIANT_FALSE ((VARIANT_BOOL)0)
#endif
#endif

#ifndef VT_EMPTY
#define VT_EMPTY 0
#define VT_NULL 1
#define VT_I2 2
#define VT_I4 3
#define VT_R4 4
#define VT_R8 5
#define VT_CY 6
#define VT_DATE 7
#define VT_BSTR 8
#define VT_DISPATCH 9
#define VT_ERROR 10
#define VT_BOOL 11
#define VT_VARIANT 12
#define VT_UNKNOWN 13
#define VT_DECIMAL 14
#define VT_I1 16
#define VT_UI1 17
#define VT_UI2 18
#define VT_UI4 19
#define VT_I8 20
#define VT_UI8 21
#define VT_INT 22
#define VT_UINT 23
#define VT_VOID 24
#define VT_HRESULT 25
#define VT_PTR 26
#define VT_SAFEARRAY 27
#define VT_CARRAY 28
#define VT_USERDEFINED 29
#define VT_LPSTR 30
#define VT_LPWSTR 31
#define VT_RECORD 36
#define VT_INT_PTR 37
#define VT_UINT_PTR 38
#define VT_FILETIME 64
#define VT_BLOB 65
#define VT_STREAM 66
#define VT_STORAGE 67
#define VT_STREAMED_OBJECT 68
#define VT_STORED_OBJECT 69
#define VT_BLOB_OBJECT 70
#define VT_CF 71
#define VT_CLSID 72
#define VT_VECTOR 0x1000
#define VT_ARRAY 0x2000
#define VT_BYREF 0x4000
#define VT_RESERVED 0x8000
#define VT_ILLEGAL 0xFFFF
#define VT_ILLEGALMASKED 0xFFF
#define VT_TYPEMASK 0xFFF
#endif

#ifndef DATE
typedef double DATE;
#endif

#ifndef DOUBLE
typedef double DOUBLE;
#endif

#ifndef SAFEARRAY
typedef struct tagSAFEARRAY SAFEARRAY;
#endif

#ifndef DECIMAL
typedef struct tagDEC {
    WORD wReserved;
    union {
        struct {
            BYTE scale;
            BYTE sign;
        } DUMMYSTRUCTNAME;
        USHORT signscale;
    } DUMMYUNIONNAME;
    ULONG Hi32;
    union {
        struct {
            ULONG Lo32;
            ULONG Mid32;
        } DUMMYSTRUCTNAME2;
        ULONGLONG Lo64;
    } DUMMYUNIONNAME2;
} DECIMAL;
#endif

typedef struct tagVARIANT {
    union {
        struct {
            WORD vt;
            WORD wReserved1;
            WORD wReserved2;
            WORD wReserved3;
            union {
                LONG lVal;
                BYTE bVal;
                SHORT iVal;
                FLOAT fltVal;
                DOUBLE dblVal;
                VARIANT_BOOL boolVal;
                DATE date;
                BSTR bstrVal;
                IUnknown *punkVal;
                void *pdispVal;
                SAFEARRAY *parray;
                BYTE *pbVal;
                SHORT *piVal;
                LONG *plVal;
                FLOAT *pfltVal;
                DOUBLE *pdblVal;
                VARIANT_BOOL *pboolVal;
                DATE *pdate;
                BSTR *pbstrVal;
            };
        };
        DECIMAL decVal;
    };
} VARIANT;

#ifndef DISPID
typedef LONG DISPID;
#endif

#ifndef LPOLESTR
typedef OLECHAR *LPOLESTR;
#endif

typedef VARIANT VARIANTARG;

#define COINIT_APARTMENTTHREADED 0x2
#define COINIT_MULTITHREADED     0x0

#ifndef CLSCTX_INPROC_SERVER
#define CLSCTX_INPROC_SERVER 0x1
#endif

#define NET_FW_IP_PROTOCOL_TCP 6
#define NET_FW_IP_PROTOCOL_UDP 17
#define NET_FW_IP_PROTOCOL_ANY 256

#define NET_FW_RULE_DIR_IN  1
#define NET_FW_RULE_DIR_OUT 2

#define NET_FW_ACTION_BLOCK 0
#define NET_FW_ACTION_ALLOW 1

#define NET_FW_PROFILE2_DOMAIN  0x1
#define NET_FW_PROFILE2_PRIVATE 0x2
#define NET_FW_PROFILE2_PUBLIC  0x4
#define NET_FW_PROFILE2_ALL     0x7fffffff

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);

DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT VOID WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG*);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count-- != 0U) {
        *d++ = (unsigned char)value;
    }
}

static wchar_t wide_tolower(wchar_t c) {
    if (c >= L'A' && c <= L'Z') return (wchar_t)(c + 32);
    return c;
}

static BOOL wide_eq_ci(const wchar_t *a, const wchar_t *b) {
    if (!a || !b) return FALSE;
    while (*a && *b) {
        if (wide_tolower(*a) != wide_tolower(*b)) return FALSE;
        a++; b++;
    }
    return (*a == L'\0' && *b == L'\0');
}

static BOOL ansi_eq(const char *a, const char *b) {
    if (!a || !b) return FALSE;
    while (*a && *b) {
        if (*a != *b) return FALSE;
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

static void sanitize_ascii(char *s) {
    if (!s) return;
    while (*s) {
        if (*s == '\r' || *s == '\n' || *s == '\t') {
            *s = ' ';
        }
        s++;
    }
}

static void trim_ascii(char *s) {
    int len;
    if (!s) return;

    len = KERNEL32$lstrlenA(s);
    while (len > 0 && s[len - 1] == ' ') {
        s[len - 1] = '\0';
        len--;
    }

    if (s[0] == '\0') return;

    {
        int start = 0;
        while (s[start] == ' ') {
            start++;
        }
        if (start > 0) {
            int i = 0;
            while (s[start + i] != '\0') {
                s[i] = s[start + i];
                i++;
            }
            s[i] = '\0';
        }
    }
}

static void truncate_with_ellipsis(char *s, int maxVisible) {
    int len;
    if (!s || maxVisible <= 0) return;
    len = KERNEL32$lstrlenA(s);
    if (len <= maxVisible) return;
    if (maxVisible <= 3) {
        s[maxVisible] = '\0';
        return;
    }
    s[maxVisible - 3] = '.';
    s[maxVisible - 2] = '.';
    s[maxVisible - 1] = '.';
    s[maxVisible] = '\0';
}

static void copy_ascii(char *dst, int dstSize, const char *src) {
    int i = 0;
    if (!dst || dstSize <= 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    while (src[i] != '\0' && i < (dstSize - 1)) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static void format_port_summary(const char *localPort, const char *remotePort, char *dst, int dstSize) {
    int pos = 0;
    int i;
    const char *lp = localPort ? localPort : "";
    const char *rp = remotePort ? remotePort : "";

    if (!dst || dstSize <= 0) return;
    dst[0] = '\0';

    if (lp[0] == '\0' && rp[0] == '\0') {
        copy_ascii(dst, dstSize, "-");
        return;
    }

    if (lp[0] != '\0') {
        const char *prefix = "L:";
        for (i = 0; prefix[i] != '\0' && pos < (dstSize - 1); i++) dst[pos++] = prefix[i];
        for (i = 0; lp[i] != '\0' && pos < (dstSize - 1); i++) dst[pos++] = lp[i];
    }

    if (rp[0] != '\0') {
        const char *prefix = lp[0] != '\0' ? " R:" : "R:";
        for (i = 0; prefix[i] != '\0' && pos < (dstSize - 1); i++) dst[pos++] = prefix[i];
        for (i = 0; rp[i] != '\0' && pos < (dstSize - 1); i++) dst[pos++] = rp[i];
    }

    dst[pos] = '\0';
    truncate_with_ellipsis(dst, 20);
}

typedef struct {
    char key[MAX_RULE_KEY_CHARS];
} RuleListKey;

static BOOL build_rule_key(const char *name, const char *dir, const char *act,
                           const char *proto, const char *enabled, const char *ports,
                           char *dst, int dstSize) {
    int pos = 0;
    int i;
    const char *parts[6];
    int part;

    if (!dst || dstSize <= 0) return FALSE;
    dst[0] = '\0';

    parts[0] = name ? name : "";
    parts[1] = dir ? dir : "";
    parts[2] = act ? act : "";
    parts[3] = proto ? proto : "";
    parts[4] = enabled ? enabled : "";
    parts[5] = ports ? ports : "";

    for (part = 0; part < 6; part++) {
        if (part != 0) {
            if (pos >= (dstSize - 1)) return FALSE;
            dst[pos++] = '|';
        }
        for (i = 0; parts[part][i] != '\0'; i++) {
            if (pos >= (dstSize - 1)) return FALSE;
            dst[pos++] = parts[part][i];
        }
    }

    dst[pos] = '\0';
    return TRUE;
}

static BOOL seen_rule_key(const RuleListKey *seen, DWORD seenCount, const char *key) {
    DWORD i;
    for (i = 0; i < seenCount; i++) {
        if (ansi_eq(seen[i].key, key)) return TRUE;
    }
    return FALSE;
}

static int wide_to_utf8(const wchar_t *src, char *dst, int dstSize) {
    int r;
    if (!dst || dstSize <= 0) return 0;
    if (!src) { dst[0] = '\0'; return 1; }
    r = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstSize, NULL, NULL);
    if (r == 0) {
        int i = 0;
        while (src[i] != L'\0' && i < (dstSize - 1)) {
            dst[i] = (char)(src[i] & 0xFF);
            i++;
        }
        dst[i] = '\0';
    }
    return r;
}

static void ansi_to_wide(const char *src, wchar_t *dst, int dstChars) {
    int converted;
    if (!dst || dstChars <= 0) return;
    if (!src) { dst[0] = L'\0'; return; }
    converted = KERNEL32$MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstChars);
    if (converted == 0) {
        int i = 0;
        while (src[i] != '\0' && i < (dstChars - 1)) {
            dst[i] = (wchar_t)(unsigned char)src[i];
            i++;
        }
        dst[i] = L'\0';
    }
}

static BOOL has_more(datap *p) {
    return (BeaconDataLength(p) > 0);
}
static const GUID CLSID_NetFwPolicy2 = {
    0xE2B3C97F, 0x6AE1, 0x41AC,
    {0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}
};

static const GUID IID_INetFwPolicy2 = {
    0x98325047, 0xC671, 0x4174,
    {0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}
};

static const GUID CLSID_NetFwRule = {
    0x2C5BC43E, 0x3369, 0x4C33,
    {0xAB, 0x0C, 0xBE, 0x94, 0x69, 0x67, 0x7A, 0xF4}
};

static const GUID IID_INetFwRule = {
    0xAF230D27, 0xBABA, 0x4E42,
    {0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2}
};

static const GUID IID_INetFwRules = {
    0x9C4C6277, 0x5027, 0x441E,
    {0xAF, 0xAE, 0xCA, 0x1F, 0x54, 0x2D, 0xA0, 0x09}
};

static const GUID IID_IEnumVARIANT = {
    0x00020404, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

typedef struct INetFwRule INetFwRule;
typedef struct INetFwRuleVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(INetFwRule*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(INetFwRule*);
    ULONG   (STDMETHODCALLTYPE *Release)(INetFwRule*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(INetFwRule*, UINT*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(INetFwRule*, UINT, LCID, void**);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(INetFwRule*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(INetFwRule*, DISPID, REFIID, LCID, WORD, void*, void*, void*, UINT*);
    HRESULT (STDMETHODCALLTYPE *get_Name)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_Name)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Description)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_Description)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_ApplicationName)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_ApplicationName)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_ServiceName)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_ServiceName)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Protocol)(INetFwRule*, long*);
    HRESULT (STDMETHODCALLTYPE *put_Protocol)(INetFwRule*, long);
    HRESULT (STDMETHODCALLTYPE *get_LocalPorts)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_LocalPorts)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_RemotePorts)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_RemotePorts)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_LocalAddresses)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_LocalAddresses)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_RemoteAddresses)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_RemoteAddresses)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_IcmpTypesAndCodes)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_IcmpTypesAndCodes)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Direction)(INetFwRule*, long*);
    HRESULT (STDMETHODCALLTYPE *put_Direction)(INetFwRule*, long);
    HRESULT (STDMETHODCALLTYPE *get_Interfaces)(INetFwRule*, VARIANT*);
    HRESULT (STDMETHODCALLTYPE *put_Interfaces)(INetFwRule*, VARIANT);
    HRESULT (STDMETHODCALLTYPE *get_InterfaceTypes)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_InterfaceTypes)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Enabled)(INetFwRule*, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_Enabled)(INetFwRule*, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_Grouping)(INetFwRule*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *put_Grouping)(INetFwRule*, BSTR);
    HRESULT (STDMETHODCALLTYPE *get_Profiles)(INetFwRule*, long*);
    HRESULT (STDMETHODCALLTYPE *put_Profiles)(INetFwRule*, long);
    HRESULT (STDMETHODCALLTYPE *get_EdgeTraversal)(INetFwRule*, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_EdgeTraversal)(INetFwRule*, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_Action)(INetFwRule*, long*);
    HRESULT (STDMETHODCALLTYPE *put_Action)(INetFwRule*, long);
} INetFwRuleVtbl;

struct INetFwRule {
    INetFwRuleVtbl *lpVtbl;
};

typedef struct INetFwRules INetFwRules;
typedef struct INetFwRulesVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(INetFwRules*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(INetFwRules*);
    ULONG   (STDMETHODCALLTYPE *Release)(INetFwRules*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(INetFwRules*, UINT*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(INetFwRules*, UINT, LCID, void**);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(INetFwRules*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(INetFwRules*, DISPID, REFIID, LCID, WORD, void*, void*, void*, UINT*);
    HRESULT (STDMETHODCALLTYPE *get_Count)(INetFwRules*, long*);
    HRESULT (STDMETHODCALLTYPE *Add)(INetFwRules*, INetFwRule*);
    HRESULT (STDMETHODCALLTYPE *Remove)(INetFwRules*, BSTR);
    HRESULT (STDMETHODCALLTYPE *Item)(INetFwRules*, BSTR, INetFwRule**);
    HRESULT (STDMETHODCALLTYPE *get__NewEnum)(INetFwRules*, IUnknown**);
} INetFwRulesVtbl;

struct INetFwRules {
    INetFwRulesVtbl *lpVtbl;
};

typedef struct IEnumVARIANT IEnumVARIANT;
typedef struct IEnumVARIANTVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IEnumVARIANT*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IEnumVARIANT*);
    ULONG   (STDMETHODCALLTYPE *Release)(IEnumVARIANT*);
    HRESULT (STDMETHODCALLTYPE *Next)(IEnumVARIANT*, ULONG, VARIANT*, ULONG*);
    HRESULT (STDMETHODCALLTYPE *Skip)(IEnumVARIANT*, ULONG);
    HRESULT (STDMETHODCALLTYPE *Reset)(IEnumVARIANT*);
    HRESULT (STDMETHODCALLTYPE *Clone)(IEnumVARIANT*, IEnumVARIANT**);
} IEnumVARIANTVtbl;

struct IEnumVARIANT {
    IEnumVARIANTVtbl *lpVtbl;
};

typedef struct INetFwPolicy2 INetFwPolicy2;
typedef struct INetFwPolicy2Vtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(INetFwPolicy2*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(INetFwPolicy2*);
    ULONG   (STDMETHODCALLTYPE *Release)(INetFwPolicy2*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(INetFwPolicy2*, UINT*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(INetFwPolicy2*, UINT, LCID, void**);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(INetFwPolicy2*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(INetFwPolicy2*, DISPID, REFIID, LCID, WORD, void*, void*, void*, UINT*);
    HRESULT (STDMETHODCALLTYPE *get_CurrentProfileTypes)(INetFwPolicy2*, long*);
    HRESULT (STDMETHODCALLTYPE *get_FirewallEnabled)(INetFwPolicy2*, long, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_FirewallEnabled)(INetFwPolicy2*, long, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_ExcludedInterfaces)(INetFwPolicy2*, long, VARIANT*);
    HRESULT (STDMETHODCALLTYPE *put_ExcludedInterfaces)(INetFwPolicy2*, long, VARIANT);
    HRESULT (STDMETHODCALLTYPE *get_BlockAllInboundTraffic)(INetFwPolicy2*, long, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_BlockAllInboundTraffic)(INetFwPolicy2*, long, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_NotificationsDisabled)(INetFwPolicy2*, long, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_NotificationsDisabled)(INetFwPolicy2*, long, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_UnicastResponsesToMulticastBroadcastDisabled)(INetFwPolicy2*, long, VARIANT_BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_UnicastResponsesToMulticastBroadcastDisabled)(INetFwPolicy2*, long, VARIANT_BOOL);
    HRESULT (STDMETHODCALLTYPE *get_Rules)(INetFwPolicy2*, INetFwRules**);
} INetFwPolicy2Vtbl;

struct INetFwPolicy2 {
    INetFwPolicy2Vtbl *lpVtbl;
};

typedef struct {
    int action;
    wchar_t name[MAX_WIDE];
    wchar_t dir[16];
    wchar_t actionStr[16];
    wchar_t protocol[16];
    wchar_t localport[64];
    wchar_t remoteport[64];
    wchar_t profile[32];
} FwParams;

static BOOL parse_direction_value(const wchar_t *dir, long *value) {
    if (!value) return FALSE;
    if (wide_eq_ci(dir, L"in")) {
        *value = NET_FW_RULE_DIR_IN;
        return TRUE;
    }
    if (wide_eq_ci(dir, L"out")) {
        *value = NET_FW_RULE_DIR_OUT;
        return TRUE;
    }
    return FALSE;
}

static BOOL parse_action_value(const wchar_t *act, long *value) {
    if (!value) return FALSE;
    if (wide_eq_ci(act, L"allow")) {
        *value = NET_FW_ACTION_ALLOW;
        return TRUE;
    }
    if (wide_eq_ci(act, L"block")) {
        *value = NET_FW_ACTION_BLOCK;
        return TRUE;
    }
    return FALSE;
}

static BOOL parse_protocol_value(const wchar_t *proto, long *value) {
    if (!value) return FALSE;
    if (wide_eq_ci(proto, L"tcp")) {
        *value = NET_FW_IP_PROTOCOL_TCP;
        return TRUE;
    }
    if (wide_eq_ci(proto, L"udp")) {
        *value = NET_FW_IP_PROTOCOL_UDP;
        return TRUE;
    }
    if (wide_eq_ci(proto, L"any")) {
        *value = NET_FW_IP_PROTOCOL_ANY;
        return TRUE;
    }
    return FALSE;
}

static BOOL parse_profile_value(const wchar_t *prof, long *value) {
    if (!value) return FALSE;
    if (!prof || prof[0] == L'\0' || wide_eq_ci(prof, L"all")) {
        *value = NET_FW_PROFILE2_ALL;
        return TRUE;
    }
    if (wide_eq_ci(prof, L"domain")) {
        *value = NET_FW_PROFILE2_DOMAIN;
        return TRUE;
    }
    if (wide_eq_ci(prof, L"private")) {
        *value = NET_FW_PROFILE2_PRIVATE;
        return TRUE;
    }
    if (wide_eq_ci(prof, L"public")) {
        *value = NET_FW_PROFILE2_PUBLIC;
        return TRUE;
    }
    return FALSE;
}

static BOOL is_profile_keyword(const wchar_t *w) {
    if (!w || w[0] == L'\0') return FALSE;
    return wide_eq_ci(w, L"all") || wide_eq_ci(w, L"domain") ||
           wide_eq_ci(w, L"private") || wide_eq_ci(w, L"public");
}

static const char* protocol_str(long proto) {
    switch (proto) {
        case NET_FW_IP_PROTOCOL_TCP: return "TCP";
        case NET_FW_IP_PROTOCOL_UDP: return "UDP";
        case NET_FW_IP_PROTOCOL_ANY: return "ANY";
        default: return "UNKNOWN";
    }
}

static const char* direction_str(long dir) {
    switch (dir) {
        case NET_FW_RULE_DIR_IN:  return "IN";
        case NET_FW_RULE_DIR_OUT: return "OUT";
        default: return "UNKNOWN";
    }
}

static const char* action_str(long act) {
    switch (act) {
        case NET_FW_ACTION_ALLOW: return "ALLOW";
        case NET_FW_ACTION_BLOCK: return "BLOCK";
        default: return "UNKNOWN";
    }
}

static void do_firewall_op(FwParams *params) {
    HRESULT hr;
    INetFwPolicy2 *policy = NULL;
    INetFwRules *rules = NULL;
    INetFwRule *rule = NULL;
    BSTR bstrName = NULL;
    BSTR bstrPort = NULL;
    BSTR bstrRemotePort = NULL;
    char nameA[MAX_WIDE];
    long dirValue = 0;
    long actionValue = 0;
    long protocolValue = 0;
    long profileValue = NET_FW_PROFILE2_ALL;

    inline_memset(nameA, 0, sizeof(nameA));
    wide_to_utf8(params->name, nameA, sizeof(nameA));

    hr = OLE32$CoCreateInstance(
        &CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
        &IID_INetFwPolicy2, (void**)&policy);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance(NetFwPolicy2) failed: 0x%08lx\n", (unsigned long)hr);
        return;
    }

    hr = policy->lpVtbl->get_Rules(policy, &rules);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] get_Rules failed: 0x%08lx\n", (unsigned long)hr);
        policy->lpVtbl->Release(policy);
        return;
    }

    if (params->action == 0) {
        if (!parse_direction_value(params->dir, &dirValue) ||
            !parse_action_value(params->actionStr, &actionValue) ||
            !parse_protocol_value(params->protocol, &protocolValue) ||
            !parse_profile_value(params->profile, &profileValue)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Invalid rule parameters\n");
            goto cleanup;
        }

        hr = OLE32$CoCreateInstance(
            &CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER,
            &IID_INetFwRule, (void**)&rule);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance(NetFwRule) failed: 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }

        bstrName = OLEAUT32$SysAllocString(params->name);
        if (!bstrName) {
            BeaconPrintf(CALLBACK_ERROR, "[-] SysAllocString failed\n");
            goto cleanup;
        }

        hr = rule->lpVtbl->put_Name(rule, bstrName);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set rule name: 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }
        hr = rule->lpVtbl->put_Direction(rule, dirValue);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set rule direction: 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }
        hr = rule->lpVtbl->put_Action(rule, actionValue);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set rule action: 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }
        hr = rule->lpVtbl->put_Protocol(rule, protocolValue);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set rule protocol: 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }
        hr = rule->lpVtbl->put_Profiles(rule, profileValue);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set rule profile: 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }
        hr = rule->lpVtbl->put_Enabled(rule, VARIANT_TRUE);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enable rule: 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }

        if (params->localport[0] != L'\0') {
            bstrPort = OLEAUT32$SysAllocString(params->localport);
            if (!bstrPort) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate local port string\n");
                goto cleanup;
            }
            hr = rule->lpVtbl->put_LocalPorts(rule, bstrPort);
            if (FAILED(hr)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set local port: 0x%08lx\n", (unsigned long)hr);
                goto cleanup;
            }
        }

        if (params->remoteport[0] != L'\0') {
            bstrRemotePort = OLEAUT32$SysAllocString(params->remoteport);
            if (!bstrRemotePort) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate remote port string\n");
                goto cleanup;
            }
            hr = rule->lpVtbl->put_RemotePorts(rule, bstrRemotePort);
            if (FAILED(hr)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set remote port: 0x%08lx\n", (unsigned long)hr);
                goto cleanup;
            }
        }

        hr = rules->lpVtbl->Add(rules, rule);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add rule \"%s\": 0x%08lx\n", nameA, (unsigned long)hr);
        } else {
            char dirA[8];
            char actA[8];
            char protoA[8];
            char portA[64];
            inline_memset(dirA, 0, sizeof(dirA));
            inline_memset(actA, 0, sizeof(actA));
            inline_memset(protoA, 0, sizeof(protoA));
            inline_memset(portA, 0, sizeof(portA));
            wide_to_utf8(params->dir, dirA, sizeof(dirA));
            wide_to_utf8(params->actionStr, actA, sizeof(actA));
            wide_to_utf8(params->protocol, protoA, sizeof(protoA));
            wide_to_utf8(params->localport, portA, sizeof(portA));
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Added firewall rule: name=\"%s\" dir=%s action=%s proto=%s localport=%s\n",
                         nameA, dirA, actA, protoA, portA);
        }
    } else if (params->action == 1) {
        bstrName = OLEAUT32$SysAllocString(params->name);
        if (!bstrName) {
            BeaconPrintf(CALLBACK_ERROR, "[-] SysAllocString failed\n");
            goto cleanup;
        }

        hr = rules->lpVtbl->Remove(rules, bstrName);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove rule \"%s\": 0x%08lx\n", nameA, (unsigned long)hr);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed firewall rule: \"%s\"\n", nameA);
        }
    } else if (params->action == 2) {
        bstrName = OLEAUT32$SysAllocString(params->name);
        if (!bstrName) {
            BeaconPrintf(CALLBACK_ERROR, "[-] SysAllocString failed\n");
            goto cleanup;
        }

        hr = rules->lpVtbl->Item(rules, bstrName, &rule);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Rule \"%s\" not found: 0x%08lx\n", nameA, (unsigned long)hr);
        } else {
            long proto = 0;
            long dir = 0;
            long act = 0;
            long prof = 0;
            VARIANT_BOOL enabled = VARIANT_FALSE;
            BSTR bstrLocalPort = NULL;
            BSTR bstrRemPort = NULL;

            rule->lpVtbl->get_Protocol(rule, &proto);
            rule->lpVtbl->get_Direction(rule, &dir);
            rule->lpVtbl->get_Action(rule, &act);
            rule->lpVtbl->get_Profiles(rule, &prof);
            rule->lpVtbl->get_Enabled(rule, &enabled);
            rule->lpVtbl->get_LocalPorts(rule, &bstrLocalPort);
            rule->lpVtbl->get_RemotePorts(rule, &bstrRemPort);

            const char *enabledStr = enabled == VARIANT_TRUE ? "Yes" : "No";
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Rule: %s\n", nameA);
            BeaconPrintf(CALLBACK_OUTPUT, "    Enabled:    %s\n", enabledStr);
            BeaconPrintf(CALLBACK_OUTPUT, "    Direction:  %s\n", direction_str(dir));
            BeaconPrintf(CALLBACK_OUTPUT, "    Action:     %s\n", action_str(act));
            BeaconPrintf(CALLBACK_OUTPUT, "    Protocol:   %s\n", protocol_str(proto));

            if (bstrLocalPort) {
                char lpA[64];
                inline_memset(lpA, 0, sizeof(lpA));
                wide_to_utf8(bstrLocalPort, lpA, sizeof(lpA));
                BeaconPrintf(CALLBACK_OUTPUT, "    LocalPort:  %s\n", lpA);
                OLEAUT32$SysFreeString(bstrLocalPort);
            }
            if (bstrRemPort) {
                char rpA[64];
                inline_memset(rpA, 0, sizeof(rpA));
                wide_to_utf8(bstrRemPort, rpA, sizeof(rpA));
                BeaconPrintf(CALLBACK_OUTPUT, "    RemotePort: %s\n", rpA);
                OLEAUT32$SysFreeString(bstrRemPort);
            }

            {
                char profBuf[64];
                int pos = 0;
                inline_memset(profBuf, 0, sizeof(profBuf));
                if (prof == NET_FW_PROFILE2_ALL || prof == 0x7fffffff) {
                    profBuf[0] = 'A'; profBuf[1] = 'l'; profBuf[2] = 'l'; profBuf[3] = '\0';
                } else {
                    if (prof & NET_FW_PROFILE2_DOMAIN) {
                        profBuf[pos++] = 'D'; profBuf[pos++] = 'o'; profBuf[pos++] = 'm';
                        profBuf[pos++] = 'a'; profBuf[pos++] = 'i'; profBuf[pos++] = 'n';
                    }
                    if (prof & NET_FW_PROFILE2_PRIVATE) {
                        if (pos > 0) profBuf[pos++] = ',';
                        profBuf[pos++] = 'P'; profBuf[pos++] = 'r'; profBuf[pos++] = 'i';
                        profBuf[pos++] = 'v'; profBuf[pos++] = 'a'; profBuf[pos++] = 't';
                        profBuf[pos++] = 'e';
                    }
                    if (prof & NET_FW_PROFILE2_PUBLIC) {
                        if (pos > 0) profBuf[pos++] = ',';
                        profBuf[pos++] = 'P'; profBuf[pos++] = 'u'; profBuf[pos++] = 'b';
                        profBuf[pos++] = 'l'; profBuf[pos++] = 'i'; profBuf[pos++] = 'c';
                    }
                    profBuf[pos] = '\0';
                }
                BeaconPrintf(CALLBACK_OUTPUT, "    Profiles:   %s\n", profBuf);
            }
        }
    } else if (params->action == 3) {
        IUnknown *pUnk = NULL;
        IEnumVARIANT *pEnum = NULL;
        long totalCount = 0;
        DWORD listed = 0;
        DWORD uniqueCount = 0;
        DWORD duplicateCount = 0;
        DWORD maxSeen = 0;
        RuleListKey *seenRows = NULL;

        rules->lpVtbl->get_Count(rules, &totalCount);
        if (totalCount > 0) {
            maxSeen = (DWORD)totalCount;
            seenRows = (RuleListKey *)KERNEL32$HeapAlloc(
                KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RuleListKey) * maxSeen);
            if (!seenRows) {
                BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed while preparing firewall rule list\n");
                goto cleanup;
            }
        }

        hr = rules->lpVtbl->get__NewEnum(rules, &pUnk);
        if (FAILED(hr) || !pUnk) {
            BeaconPrintf(CALLBACK_ERROR, "[-] get__NewEnum failed: 0x%08lx\n", (unsigned long)hr);
            if (seenRows) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, seenRows);
            goto cleanup;
        }

        hr = pUnk->lpVtbl->QueryInterface(pUnk, &IID_IEnumVARIANT, (void**)&pEnum);
        pUnk->lpVtbl->Release(pUnk);
        if (FAILED(hr) || !pEnum) {
            BeaconPrintf(CALLBACK_ERROR, "[-] QI IEnumVARIANT failed: 0x%08lx\n", (unsigned long)hr);
            if (seenRows) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, seenRows);
            goto cleanup;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerating firewall rules (deduplicated view, cap: %d)\n", MAX_ENUM_RULES);

        while (1) {
            VARIANT var;
            ULONG fetched = 0;
            INetFwRule *iterRule = NULL;
            BSTR bstrRuleName = NULL;
            BSTR bstrLPort = NULL;
            BSTR bstrRPort = NULL;
            long rProto = 0;
            long rDir = 0;
            long rAct = 0;
            VARIANT_BOOL rEnabled = VARIANT_FALSE;
            char rNameFull[MAX_RULE_NAME_CHARS];
            char rLocalPortA[48];
            char rRemotePortA[48];
            char rPortDisplay[MAX_RULE_PORT_CHARS];
            char ruleKey[MAX_RULE_KEY_CHARS];
            const char *enabledShort;

            inline_memset(&var, 0, sizeof(var));

            hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &fetched);
            if (hr != S_OK || fetched == 0) break;

            if (var.vt != VT_DISPATCH || !var.pdispVal) {
                OLEAUT32$VariantClear(&var);
                continue;
            }

            hr = ((IUnknown*)var.pdispVal)->lpVtbl->QueryInterface(
                (IUnknown*)var.pdispVal, &IID_INetFwRule, (void**)&iterRule);
            OLEAUT32$VariantClear(&var);

            if (FAILED(hr) || !iterRule) continue;

            iterRule->lpVtbl->get_Name(iterRule, &bstrRuleName);
            iterRule->lpVtbl->get_Protocol(iterRule, &rProto);
            iterRule->lpVtbl->get_Direction(iterRule, &rDir);
            iterRule->lpVtbl->get_Action(iterRule, &rAct);
            iterRule->lpVtbl->get_Enabled(iterRule, &rEnabled);
            iterRule->lpVtbl->get_LocalPorts(iterRule, &bstrLPort);
            iterRule->lpVtbl->get_RemotePorts(iterRule, &bstrRPort);

            inline_memset(rNameFull, 0, sizeof(rNameFull));
            inline_memset(rLocalPortA, 0, sizeof(rLocalPortA));
            inline_memset(rRemotePortA, 0, sizeof(rRemotePortA));
            inline_memset(rPortDisplay, 0, sizeof(rPortDisplay));
            inline_memset(ruleKey, 0, sizeof(ruleKey));

            if (bstrRuleName) {
                wide_to_utf8(bstrRuleName, rNameFull, sizeof(rNameFull));
                OLEAUT32$SysFreeString(bstrRuleName);
            }
            if (bstrLPort) {
                wide_to_utf8(bstrLPort, rLocalPortA, sizeof(rLocalPortA));
                OLEAUT32$SysFreeString(bstrLPort);
            }
            if (bstrRPort) {
                wide_to_utf8(bstrRPort, rRemotePortA, sizeof(rRemotePortA));
                OLEAUT32$SysFreeString(bstrRPort);
            }

            sanitize_ascii(rNameFull);
            sanitize_ascii(rLocalPortA);
            sanitize_ascii(rRemotePortA);
            trim_ascii(rNameFull);
            trim_ascii(rLocalPortA);
            trim_ascii(rRemotePortA);

            if (rNameFull[0] == '\0') {
                copy_ascii(rNameFull, sizeof(rNameFull), "(unnamed)");
            }

            format_port_summary(rLocalPortA, rRemotePortA, rPortDisplay, sizeof(rPortDisplay));
            enabledShort = rEnabled == VARIANT_TRUE ? "Y" : "N";

            if (!build_rule_key(rNameFull, direction_str(rDir), action_str(rAct),
                                protocol_str(rProto), enabledShort, rPortDisplay,
                                ruleKey, sizeof(ruleKey))) {
                copy_ascii(ruleKey, sizeof(ruleKey), rNameFull);
            }

            if (seenRows && seen_rule_key(seenRows, uniqueCount, ruleKey)) {
                duplicateCount++;
                iterRule->lpVtbl->Release(iterRule);
                continue;
            }

            if (seenRows && uniqueCount < maxSeen) {
                copy_ascii(seenRows[uniqueCount].key, sizeof(seenRows[uniqueCount].key), ruleKey);
            }
            uniqueCount++;

            if (listed < MAX_ENUM_RULES) {
                const char *lpShow = (rLocalPortA[0] != '\0') ? rLocalPortA : "-";
                const char *rpShow = (rRemotePortA[0] != '\0') ? rRemotePortA : "-";
                const char *enabledLong = (rEnabled == VARIANT_TRUE) ? "Yes" : "No";

                BeaconPrintf(CALLBACK_OUTPUT, "[+] Rule %lu: %s\n",
                             (unsigned long)(listed + 1), rNameFull);
                BeaconPrintf(CALLBACK_OUTPUT,
                             "    Direction: %s | Action: %s | Protocol: %s | Enabled: %s\n",
                             direction_str(rDir),
                             action_str(rAct),
                             protocol_str(rProto),
                             enabledLong);
                BeaconPrintf(CALLBACK_OUTPUT, "    LocalPort: %s | RemotePort: %s\n",
                             lpShow, rpShow);
                listed++;
            }

            iterRule->lpVtbl->Release(iterRule);
        }

        pEnum->lpVtbl->Release(pEnum);
        if (seenRows) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, seenRows);

        BeaconPrintf(CALLBACK_OUTPUT, "[i] %ld firewall rules total, %lu unique rows\n",
                     totalCount, (unsigned long)uniqueCount);

        if (uniqueCount > MAX_ENUM_RULES) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] ... %lu unique rows not shown (cap: %d)\n",
                         (unsigned long)(uniqueCount - MAX_ENUM_RULES), MAX_ENUM_RULES);
        }
        if (duplicateCount > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Suppressed %lu duplicate rows\n", (unsigned long)duplicateCount);
        }
    }

cleanup:
    if (bstrRemotePort) OLEAUT32$SysFreeString(bstrRemotePort);
    if (bstrPort) OLEAUT32$SysFreeString(bstrPort);
    if (bstrName) OLEAUT32$SysFreeString(bstrName);
    if (rule) rule->lpVtbl->Release(rule);
    if (rules) rules->lpVtbl->Release(rules);
    if (policy) policy->lpVtbl->Release(policy);
}

static DWORD WINAPI StaThread(LPVOID lpParameter) {
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr) || hr == S_FALSE) {
        do_firewall_op((FwParams *)lpParameter);
        OLE32$CoUninitialize();
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx(STA thread) failed: 0x%08lx\n", (unsigned long)hr);
    }
    return 0;
}

static void print_usage(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] firewall_rule <add|remove|query|list> <args...>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] add: <name> <dir> <action> <protocol> [localport] [remoteport|profile] [profile]\n");
    BeaconPrintf(CALLBACK_OUTPUT, " [x] dir: in | out\n");
    BeaconPrintf(CALLBACK_OUTPUT, " [x] action:   allow | block\n");
    BeaconPrintf(CALLBACK_OUTPUT, " [x] protocol: tcp | udp | any\n");
    BeaconPrintf(CALLBACK_OUTPUT, " [x] localport: required for tcp/udp, empty or omitted for any\n");
    BeaconPrintf(CALLBACK_OUTPUT, " [x] profile:  domain | private | public | all (default: all)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] remove: <name>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] query: <name>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] list: (no args, enumerates all rules but capped at %d (can be changed))\n", MAX_ENUM_RULES);
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    char *subcmd = NULL;
    char *name = NULL;
    FwParams *params = NULL;
    HRESULT hr;
    HANDLE hThread = NULL;
    HANDLE heap = NULL;
    BOOL comInitialized = FALSE;

    if (alen == 0) {
        print_usage();
        return;
    }

    heap = KERNEL32$GetProcessHeap();
    if (!heap) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcessHeap failed: 0x%08lx\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    params = (FwParams *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(FwParams));
    if (!params) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed: 0x%08lx\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconDataParse(&parser, args, (int)alen);
    subcmd = BeaconDataExtract(&parser, NULL);

    if (!subcmd || !subcmd[0]) {
        print_usage();
        goto cleanup;
    }

    {
        wchar_t subcmdW[32];
        inline_memset(subcmdW, 0, sizeof(subcmdW));
        ansi_to_wide(subcmd, subcmdW, ARRAYSIZE(subcmdW));

        if (wide_eq_ci(subcmdW, L"add")) {
            params->action = 0;
        } else if (wide_eq_ci(subcmdW, L"remove")) {
            params->action = 1;
        } else if (wide_eq_ci(subcmdW, L"query")) {
            params->action = 2;
        } else if (wide_eq_ci(subcmdW, L"list")) {
            params->action = 3;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Unknown subcommand: %s\n", subcmd);
            print_usage();
            goto cleanup;
        }
    }

    if (params->action != 3) {
        name = BeaconDataExtract(&parser, NULL);
        if (!name || !name[0]) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Rule name required\n");
            goto cleanup;
        }
        ansi_to_wide(name, params->name, ARRAYSIZE(params->name));
    }

    if (params->action == 0) {
        char *dir = NULL;
        char *act = NULL;
        char *proto = NULL;
        char *lport = NULL;
        char *prof = NULL;

        dir = BeaconDataExtract(&parser, NULL);
        act = BeaconDataExtract(&parser, NULL);
        proto = BeaconDataExtract(&parser, NULL);
        lport = BeaconDataExtract(&parser, NULL);

        if (!dir || !dir[0] || !act || !act[0] || !proto || !proto[0]) {
            BeaconPrintf(CALLBACK_ERROR, "[-] add requires: name dir action protocol [localport] [remoteport] [profile]\n");
            goto cleanup;
        }

        ansi_to_wide(dir, params->dir, ARRAYSIZE(params->dir));
        ansi_to_wide(act, params->actionStr, ARRAYSIZE(params->actionStr));
        ansi_to_wide(proto, params->protocol, ARRAYSIZE(params->protocol));
        if (lport && lport[0]) {
            ansi_to_wide(lport, params->localport, ARRAYSIZE(params->localport));
        }

        if (has_more(&parser)) {
            char *opt1 = NULL;
            wchar_t opt1W[32];
            opt1 = BeaconDataExtract(&parser, NULL);
            if (opt1 && opt1[0]) {
                inline_memset(opt1W, 0, sizeof(opt1W));
                ansi_to_wide(opt1, opt1W, ARRAYSIZE(opt1W));
                if (is_profile_keyword(opt1W)) {
                    ansi_to_wide(opt1, params->profile, ARRAYSIZE(params->profile));
                } else {
                    ansi_to_wide(opt1, params->remoteport, ARRAYSIZE(params->remoteport));
                    if (has_more(&parser)) {
                        prof = BeaconDataExtract(&parser, NULL);
                        if (prof && prof[0]) {
                            ansi_to_wide(prof, params->profile, ARRAYSIZE(params->profile));
                        }
                    }
                }
            }
        }

        {
            long dirCheck = 0;
            long actCheck = 0;
            long protoCheck = 0;
            long profCheck = 0;

            if (!parse_direction_value(params->dir, &dirCheck)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Invalid direction: use in or out\n");
                goto cleanup;
            }
            if (!parse_action_value(params->actionStr, &actCheck)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Invalid action: use allow or block\n");
                goto cleanup;
            }
            if (!parse_protocol_value(params->protocol, &protoCheck)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Invalid protocol: use tcp, udp, or any\n");
                goto cleanup;
            }
            if (!parse_profile_value(params->profile, &profCheck)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Invalid profile: use domain, private, public, or all\n");
                goto cleanup;
            }

            if (protoCheck == NET_FW_IP_PROTOCOL_ANY) {
                if (params->localport[0] != L'\0' || params->remoteport[0] != L'\0') {
                    BeaconPrintf(CALLBACK_ERROR, "[-] Protocol any cannot be combined with localport or remoteport\n");
                    goto cleanup;
                }
            } else if (params->localport[0] == L'\0') {
                BeaconPrintf(CALLBACK_ERROR, "[-] localport is required for tcp or udp rules\n");
                goto cleanup;
            }
        }
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hr == RPC_E_CHANGED_MODE) {
        hThread = KERNEL32$CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)StaThread, (LPVOID)params, 0, NULL);
        if (hThread) {
            DWORD waitResult = KERNEL32$WaitForSingleObject(hThread, INFINITE);
            if (waitResult != WAIT_OBJECT_0) {
                BeaconPrintf(CALLBACK_ERROR, "[-] WaitForSingleObject failed: 0x%08lx\n", (unsigned long)KERNEL32$GetLastError());
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] CreateThread failed: 0x%08lx\n", (unsigned long)KERNEL32$GetLastError());
        }
        goto cleanup;
    }

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx failed: 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }
    comInitialized = TRUE;

    do_firewall_op(params);

cleanup:
    if (comInitialized) OLE32$CoUninitialize();
    if (hThread) KERNEL32$CloseHandle(hThread);
    if (params) KERNEL32$HeapFree(heap, 0, params);
}
