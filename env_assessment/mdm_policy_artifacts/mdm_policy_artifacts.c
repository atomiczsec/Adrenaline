#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"


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
#define VARIANT_TRUE ((VARIANT_BOOL)-1)
#define VARIANT_FALSE ((VARIANT_BOOL)0)
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

typedef VARIANT *LPVARIANT;


typedef struct ITaskService ITaskService;
typedef struct ITaskFolder ITaskFolder;
typedef struct IRegisteredTaskCollection IRegisteredTaskCollection;
typedef struct IRegisteredTask IRegisteredTask;
typedef struct ITaskFolderCollection ITaskFolderCollection;
typedef struct IRunningTask IRunningTask;
typedef struct IRunningTaskCollection IRunningTaskCollection;
typedef struct ITaskDefinition ITaskDefinition;

typedef struct ITaskServiceVtbl {
    struct IUnknownVtbl base;
    HRESULT (STDMETHODCALLTYPE *Connect)(ITaskService *This, VARIANT serverName, VARIANT user, VARIANT domain, VARIANT password);
    HRESULT (STDMETHODCALLTYPE *get_Connected)(ITaskService *This, VARIANT_BOOL *pConnected);
    HRESULT (STDMETHODCALLTYPE *get_TargetServer)(ITaskService *This, BSTR *pServer);
    HRESULT (STDMETHODCALLTYPE *get_ConnectedUser)(ITaskService *This, BSTR *pUser);
    HRESULT (STDMETHODCALLTYPE *get_ConnectedDomain)(ITaskService *This, BSTR *pDomain);
    HRESULT (STDMETHODCALLTYPE *get_HighestVersion)(ITaskService *This, DWORD *pVersion);
    HRESULT (STDMETHODCALLTYPE *GetFolder)(ITaskService *This, BSTR path, ITaskFolder **ppFolder);
    HRESULT (STDMETHODCALLTYPE *GetRunningTasks)(ITaskService *This, LONG flags, void **ppRunningTasks);
    HRESULT (STDMETHODCALLTYPE *NewTask)(ITaskService *This, DWORD flags, void **ppDefinition);
} ITaskServiceVtbl;

struct ITaskService {
    CONST_VTBL ITaskServiceVtbl *lpVtbl;
};

#ifndef TASK_LOGON_TYPE
typedef enum {
    TASK_LOGON_NONE = 0,
    TASK_LOGON_PASSWORD = 1,
    TASK_LOGON_S4U = 2,
    TASK_LOGON_INTERACTIVE_TOKEN = 3,
    TASK_LOGON_GROUP = 4,
    TASK_LOGON_SERVICE_ACCOUNT = 5,
    TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6
} TASK_LOGON_TYPE;
#endif

typedef struct ITaskFolderVtbl {
    struct IUnknownVtbl base;
    HRESULT (STDMETHODCALLTYPE *get_Name)(ITaskFolder *This, BSTR *pName);
    HRESULT (STDMETHODCALLTYPE *get_Path)(ITaskFolder *This, BSTR *pPath);
    HRESULT (STDMETHODCALLTYPE *GetFolder)(ITaskFolder *This, BSTR path, ITaskFolder **ppFolder);
    HRESULT (STDMETHODCALLTYPE *CreateFolder)(ITaskFolder *This, BSTR subFolderName, VARIANT sddl, ITaskFolder **ppFolder);
    HRESULT (STDMETHODCALLTYPE *DeleteFolder)(ITaskFolder *This, BSTR folderName, LONG flags);
    HRESULT (STDMETHODCALLTYPE *GetTask)(ITaskFolder *This, BSTR path, IRegisteredTask **ppTask);
    HRESULT (STDMETHODCALLTYPE *GetTasks)(ITaskFolder *This, LONG flags, IRegisteredTaskCollection **ppTasks);
    HRESULT (STDMETHODCALLTYPE *DeleteTask)(ITaskFolder *This, BSTR name, LONG flags);
    HRESULT (STDMETHODCALLTYPE *RegisterTaskDefinition)(ITaskFolder *This, BSTR path, ITaskDefinition *pDefinition, LONG flags, VARIANT userId, VARIANT password, TASK_LOGON_TYPE logonType, VARIANT sddl, IRegisteredTask **ppTask);
    HRESULT (STDMETHODCALLTYPE *GetSecurityDescriptor)(ITaskFolder *This, LONG securityInformation, BSTR *pSddl);
    HRESULT (STDMETHODCALLTYPE *SetSecurityDescriptor)(ITaskFolder *This, BSTR sddl, LONG flags);
    HRESULT (STDMETHODCALLTYPE *GetFolders)(ITaskFolder *This, LONG flags, ITaskFolderCollection **ppFolders);
} ITaskFolderVtbl;

struct ITaskFolder {
    CONST_VTBL ITaskFolderVtbl *lpVtbl;
};

typedef struct IRegisteredTaskCollectionVtbl {
    struct IUnknownVtbl base;
    HRESULT (STDMETHODCALLTYPE *get_Count)(IRegisteredTaskCollection *This, LONG *pCount);
    HRESULT (STDMETHODCALLTYPE *get_Item)(IRegisteredTaskCollection *This, VARIANT index, IRegisteredTask **ppTask);
    HRESULT (STDMETHODCALLTYPE *get__NewEnum)(IRegisteredTaskCollection *This, IUnknown **ppEnum);
} IRegisteredTaskCollectionVtbl;

struct IRegisteredTaskCollection {
    CONST_VTBL IRegisteredTaskCollectionVtbl *lpVtbl;
};

#ifndef TASK_STATE
typedef enum _TASK_STATE {
    TASK_STATE_UNKNOWN = 0,
    TASK_STATE_DISABLED = 1,
    TASK_STATE_QUEUED = 2,
    TASK_STATE_READY = 3,
    TASK_STATE_RUNNING = 4
} TASK_STATE;
#endif

typedef struct IRegisteredTaskVtbl {
    struct IUnknownVtbl base;
    HRESULT (STDMETHODCALLTYPE *get_Name)(IRegisteredTask *This, BSTR *pName);
    HRESULT (STDMETHODCALLTYPE *get_Path)(IRegisteredTask *This, BSTR *pPath);
    HRESULT (STDMETHODCALLTYPE *get_State)(IRegisteredTask *This, TASK_STATE *pState);
    HRESULT (STDMETHODCALLTYPE *get_Enabled)(IRegisteredTask *This, VARIANT_BOOL *pEnabled);
    HRESULT (STDMETHODCALLTYPE *put_Enabled)(IRegisteredTask *This, VARIANT_BOOL enabled);
    HRESULT (STDMETHODCALLTYPE *Run)(IRegisteredTask *This, VARIANT params, IRunningTask **ppRunningTask);
    HRESULT (STDMETHODCALLTYPE *RunEx)(IRegisteredTask *This, VARIANT params, LONG flags, LONG sessionID, BSTR user, IRunningTask **ppRunningTask);
    HRESULT (STDMETHODCALLTYPE *GetInstances)(IRegisteredTask *This, LONG flags, IRunningTaskCollection **ppRunningTasks);
    HRESULT (STDMETHODCALLTYPE *get_LastRunTime)(IRegisteredTask *This, DATE *pLastRunTime);
    HRESULT (STDMETHODCALLTYPE *get_LastTaskResult)(IRegisteredTask *This, LONG *pLastTaskResult);
    HRESULT (STDMETHODCALLTYPE *get_NumberOfMissedRuns)(IRegisteredTask *This, LONG *pNumberOfMissedRuns);
    HRESULT (STDMETHODCALLTYPE *get_NextRunTime)(IRegisteredTask *This, DATE *pNextRunTime);
    HRESULT (STDMETHODCALLTYPE *get_Definition)(IRegisteredTask *This, ITaskDefinition **ppDefinition);
    HRESULT (STDMETHODCALLTYPE *get_Xml)(IRegisteredTask *This, BSTR *pXml);
    HRESULT (STDMETHODCALLTYPE *GetSecurityDescriptor)(IRegisteredTask *This, LONG securityInformation, BSTR *pSddl);
    HRESULT (STDMETHODCALLTYPE *SetSecurityDescriptor)(IRegisteredTask *This, BSTR sddl, LONG flags);
    HRESULT (STDMETHODCALLTYPE *Stop)(IRegisteredTask *This, LONG flags);
    HRESULT (STDMETHODCALLTYPE *GetRunTimes)(IRegisteredTask *This, LPSYSTEMTIME pstStart, LPSYSTEMTIME pstEnd, DWORD *pCount, LPSYSTEMTIME **ppRunTimes);
} IRegisteredTaskVtbl;

struct IRegisteredTask {
    CONST_VTBL IRegisteredTaskVtbl *lpVtbl;
};

typedef struct ITaskFolderCollectionVtbl {
    struct IUnknownVtbl base;
    HRESULT (STDMETHODCALLTYPE *get_Count)(ITaskFolderCollection *This, LONG *pCount);
    HRESULT (STDMETHODCALLTYPE *get_Item)(ITaskFolderCollection *This, VARIANT index, ITaskFolder **ppFolder);
    HRESULT (STDMETHODCALLTYPE *get__NewEnum)(ITaskFolderCollection *This, IUnknown **ppEnum);
} ITaskFolderCollectionVtbl;

struct ITaskFolderCollection {
    CONST_VTBL ITaskFolderCollectionVtbl *lpVtbl;
};

#ifndef TASK_ENUM_HIDDEN
#define TASK_ENUM_HIDDEN 0x1
#endif

#ifndef TASK_STATE_UNKNOWN
#define TASK_STATE_UNKNOWN 0
#define TASK_STATE_DISABLED 1
#define TASK_STATE_QUEUED 2
#define TASK_STATE_READY 3
#define TASK_STATE_RUNNING 4
#endif

#ifndef IID
typedef GUID IID;
#endif

#ifndef CLSID
typedef GUID CLSID;
#endif

#ifndef REFIID
typedef const IID *REFIID;
#endif

#ifndef REFCLSID
typedef const CLSID *REFCLSID;
#endif

const CLSID CLSID_TaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
const IID IID_ITaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT VOID WINAPI OLE32$CoUninitialize(VOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT VOID WINAPI OLEAUT32$VariantInit(VARIANT*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANT*);
DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT VOID WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VarFormatDateTime(VARIANT*, int, int, BSTR*);

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

#ifndef REG_QWORD
#define REG_QWORD 11
#endif

#ifndef S_OK
#define S_OK ((HRESULT)0x00000000L)
#endif

#ifndef S_FALSE
#define S_FALSE ((HRESULT)0x00000001L)
#endif

#ifndef FAILED
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#endif

#ifndef SUCCEEDED
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#endif

#ifndef RPC_C_AUTHN_LEVEL_DEFAULT
#define RPC_C_AUTHN_LEVEL_DEFAULT 0
#endif

#ifndef RPC_C_IMP_LEVEL_IMPERSONATE
#define RPC_C_IMP_LEVEL_IMPERSONATE 3
#endif

#ifndef EOAC_NONE
#define EOAC_NONE 0
#endif

#ifndef CLSCTX_INPROC_SERVER
#define CLSCTX_INPROC_SERVER 0x1
#endif

#ifndef COINIT_APARTMENTTHREADED
#define COINIT_APARTMENTTHREADED 0x2
#endif

#define MAX_KEY_PATH 512
#define MAX_VALUE_NAME 256
#define MAX_VALUE_DATA 2048
#define MAX_DATA_STRING 1024
#define MAX_GUID_STRING 64
#define MAX_ENROLLMENT_GUIDS 32

// Scoring model 
typedef struct {
    int join_state_mdm_url;      // dsregcmd /status equivalent (3 points)
    int enterprisemgmt_tasks;     // EnterpriseMgmt scheduled tasks (2 points)
    int mdm_config_policy;        // MDM configuration policy (2 points)
    int intune_evidence;          // Intune enrollment evidence (2 points)
    int enrollments_registry;    // Enrollments registry (1 point)
    int total_score;              // Total score (max 10)
} mdm_score_t;


typedef struct {
    wchar_t guid[MAX_GUID_STRING];
    int found_in_enrollments;
    int found_in_tracked;
    int found_in_providers;
    int found_in_tasks;
} enrollment_guid_t;

typedef struct {
    const wchar_t *path_prefix;
    const wchar_t *value_name;
    const char *meaning;
} policy_whitelist_entry;

typedef struct {
    DWORD subkeys_scanned;
    DWORD matches;
    DWORD values_printed;
    DWORD access_denied;
    mdm_score_t score;
    enrollment_guid_t enrollment_guids[MAX_ENROLLMENT_GUIDS];
    int enrollment_guid_count;
} scan_counters;

static const policy_whitelist_entry g_whitelist[] = {
    {L"SOFTWARE\\Microsoft\\PolicyManager\\current\\device", L"RequireDeviceCompliance", "Observed policy artifact: Device compliance requirement"},
    {L"SOFTWARE\\Microsoft\\PolicyManager\\current\\device", L"RequireMfa", "Observed policy artifact: MFA requirement"},
    {L"SOFTWARE\\Microsoft\\PolicyManager\\current\\device", L"Compliant", "Observed policy artifact: Device compliance state flag"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", "Observed policy artifact: User Account Control enabled"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"FilterAdministratorToken", "Observed policy artifact: Admin approval mode for built-in Administrator"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication", L"EnableAADCloudAPPlugin", "Observed policy artifact: Azure AD authentication plugin enabled"},
    {L"SOFTWARE\\Microsoft\\Enrollments", L"EnrollmentState", "Observed policy artifact: MDM enrollment state"},
    {L"SOFTWARE\\Microsoft\\Enrollments", L"EnrollmentType", "Observed policy artifact: MDM enrollment type"},
    {L"SOFTWARE\\Microsoft\\Enrollments", L"AADDeviceID", "Observed policy artifact: Azure AD device ID"},
    {L"SOFTWARE\\Microsoft\\Enrollments", L"TenantID", "Observed policy artifact: Azure AD tenant ID"},
    {L"SOFTWARE\\Microsoft\\EnterpriseResourceManager\\Tracked", L"LastSyncTime", "Observed policy artifact: Enterprise resource manager last sync time"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MDM", L"MDMDeviceID", "Observed policy artifact: MDM device identifier"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MDM", L"EnrollmentDeviceID", "Observed policy artifact: Enrollment device identifier"}
};

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static void inline_memcpy(void *dest, const void *src, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (count--) {
        *d++ = *s++;
    }
}

static size_t inline_strlen(const char *s) {
    size_t i = 0;
    if (!s) return 0;
    while (s[i]) {
        i++;
    }
    return i;
}

static size_t inline_wcslen(const wchar_t *s) {
    size_t i = 0;
    if (!s) return 0;
    while (s[i]) {
        i++;
    }
    return i;
}

static wchar_t ascii_towlower(wchar_t c) {
    if (c >= L'A' && c <= L'Z') {
        return (wchar_t)(c + 32);
    }
    return c;
}

static int wcs_prefix_ci(const wchar_t *text, const wchar_t *prefix) {
    size_t i = 0;
    if (!text || !prefix) return 0;
    while (prefix[i]) {
        if (!text[i]) return 0;
        if (ascii_towlower(text[i]) != ascii_towlower(prefix[i])) {
            return 0;
        }
        i++;
    }
    return 1;
}

static int wcs_equal_ci(const wchar_t *a, const wchar_t *b) {
    size_t i = 0;
    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        if (ascii_towlower(a[i]) != ascii_towlower(b[i])) {
            return 0;
        }
        i++;
    }
    return a[i] == b[i];
}

static int wide_to_utf8_len(const wchar_t *src, size_t src_len_bytes, char *dst, size_t dst_size) {
    int result;
    int src_len_chars;
    if (!src || !dst || dst_size == 0 || src_len_bytes == 0) return 0;
    inline_memset(dst, 0, dst_size);
    src_len_chars = (int)(src_len_bytes / sizeof(wchar_t));
    result = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, src_len_chars, dst, (int)dst_size, NULL, NULL);
    return result != 0;
}

static int wide_to_utf8(const wchar_t *src, char *dst, size_t dst_size) {
    size_t src_len_bytes;
    if (!src || !dst || dst_size == 0) return 0;
    src_len_bytes = (inline_wcslen(src) + 1) * sizeof(wchar_t);
    return wide_to_utf8_len(src, src_len_bytes, dst, dst_size);
}


static const char *registry_type_name(DWORD type) {
    switch (type) {
        case REG_DWORD:
            return "REG_DWORD";
        case REG_QWORD:
            return "REG_QWORD";
        case REG_SZ:
            return "REG_SZ";
        case REG_EXPAND_SZ:
            return "REG_EXPAND_SZ";
        case REG_MULTI_SZ:
            return "REG_MULTI_SZ";
        case REG_BINARY:
            return "REG_BINARY";
        default:
            return "REG_UNKNOWN";
    }
}

static void u64_to_string(unsigned long long value, char *out, size_t out_size) {
    char tmp[32];
    size_t i = 0;
    size_t j = 0;
    if (!out || out_size == 0) return;
    if (value == 0) {
        if (out_size > 1) {
            out[0] = '0';
            out[1] = '\0';
        } else {
            out[0] = '\0';
        }
        return;
    }
    while (value && i + 1 < sizeof(tmp)) {
        tmp[i++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (i > 0 && j + 1 < out_size) {
        out[j++] = tmp[--i];
    }
    out[j] = '\0';
}

static void binary_to_hex(const BYTE *data, DWORD data_size, char *out, size_t out_size) {
    const char hex[] = "0123456789ABCDEF";
    size_t out_index = 0;
    if (!out || out_size == 0) return;
    inline_memset(out, 0, out_size);
    for (DWORD i = 0; i < data_size && out_index + 3 < out_size; i++) {
        out[out_index++] = hex[(data[i] >> 4) & 0xF];
        out[out_index++] = hex[data[i] & 0xF];
        if (i + 1 < data_size && out_index + 1 < out_size) {
            out[out_index++] = ' ';
        }
    }
    out[out_index] = '\0';
}

static void multi_sz_to_utf8_bounded(const wchar_t *data, DWORD data_size_bytes, char *out, size_t out_size) {
    size_t out_index = 0;
    const wchar_t *ptr = data;
    const wchar_t *data_end;
    int first = 1;
    if (!data || !out || out_size == 0 || data_size_bytes == 0) return;
    inline_memset(out, 0, out_size);
    data_end = (const wchar_t *)((const unsigned char *)data + data_size_bytes);
    while (ptr < data_end && *ptr) {
        const wchar_t *segment_start = ptr;
        const wchar_t *segment_end = segment_start;
        size_t segment_len_bytes = 0;
        char segment[MAX_DATA_STRING];
        size_t segment_len;
        
        while (segment_end < data_end && *segment_end) {
            segment_end++;
        }
        segment_len_bytes = (size_t)((const unsigned char *)segment_end - (const unsigned char *)segment_start);
        if (segment_end < data_end && *segment_end == L'\0') {
            segment_len_bytes += sizeof(wchar_t);
        }
        
        inline_memset(segment, 0, sizeof(segment));
        wide_to_utf8_len(segment_start, segment_len_bytes, segment, sizeof(segment));
        segment_len = inline_strlen(segment);
        
        if (!first && out_index + 2 < out_size) {
            out[out_index++] = ';';
            out[out_index++] = ' ';
        }
        for (size_t i = 0; i < segment_len && out_index + 1 < out_size; i++) {
            out[out_index++] = segment[i];
        }
        first = 0;
        
        if (segment_end < data_end) {
            ptr = segment_end + 1;
        } else {
            break;
        }
    }
    out[out_index] = '\0';
}

static void build_rooted_path(const wchar_t *key_path, wchar_t *out, size_t out_size) {
    const wchar_t *root = L"HKLM\\";
    size_t idx = 0;
    size_t i = 0;
    if (!out || out_size == 0) return;
    inline_memset(out, 0, out_size * sizeof(wchar_t));
    while (root[i] && idx + 1 < out_size) {
        out[idx++] = root[i++];
    }
    i = 0;
    while (key_path && key_path[i] && idx + 1 < out_size) {
        out[idx++] = key_path[i++];
    }
    out[idx] = L'\0';
}

static int build_subkey_path(const wchar_t *base, const wchar_t *sub, wchar_t *out, size_t out_size) {
    size_t idx = 0;
    size_t i = 0;
    if (!base || !sub || !out || out_size == 0) return 0;
    inline_memset(out, 0, out_size * sizeof(wchar_t));
    while (base[i] && idx + 1 < out_size) {
        out[idx++] = base[i++];
    }
    if (idx + 1 < out_size) {
        out[idx++] = L'\\';
    }
    i = 0;
    while (sub[i] && idx + 1 < out_size) {
        out[idx++] = sub[i++];
    }
    out[idx] = L'\0';
    return 1;
}

// Find or add enrollment GUID to tracking
static enrollment_guid_t *find_or_add_enrollment_guid(scan_counters *counters, const wchar_t *guid) {
    int i;
    for (i = 0; i < counters->enrollment_guid_count && i < MAX_ENROLLMENT_GUIDS; i++) {
        if (wcs_equal_ci(counters->enrollment_guids[i].guid, guid)) {
            return &counters->enrollment_guids[i];
        }
    }
    if (i < MAX_ENROLLMENT_GUIDS) {
        inline_memset(&counters->enrollment_guids[i], 0, sizeof(enrollment_guid_t));
        size_t guid_len = inline_wcslen(guid);
        if (guid_len < MAX_GUID_STRING) {
            inline_memcpy(counters->enrollment_guids[i].guid, guid, guid_len * sizeof(wchar_t));
            counters->enrollment_guids[i].guid[guid_len] = L'\0';
            counters->enrollment_guid_count++;
            return &counters->enrollment_guids[i];
        }
    }
    return NULL;
}

static int extract_guid_from_path(const wchar_t *path, wchar_t *guid_out, size_t guid_out_size) {
    const wchar_t *guid_start = NULL;
    const wchar_t *p = path;
    size_t i = 0;
    
    // Find last backslash
    while (*p) {
        if (*p == L'\\') {
            guid_start = p + 1;
        }
        p++;
    }
    
    if (!guid_start) return 0;
    
    
    while (guid_start[i] && guid_start[i] != L'\\' && i + 1 < guid_out_size) {
        guid_out[i] = guid_start[i];
        i++;
    }
    guid_out[i] = L'\0';
    
    
    return (i > 0 && guid_out[0] == L'{');
}

static const policy_whitelist_entry *find_whitelist_match(const wchar_t *path, const wchar_t *value_name) {
    size_t count = sizeof(g_whitelist) / sizeof(g_whitelist[0]);
    for (size_t i = 0; i < count; i++) {
        if (wcs_prefix_ci(path, g_whitelist[i].path_prefix) &&
            wcs_equal_ci(value_name, g_whitelist[i].value_name)) {
            return &g_whitelist[i];
        }
    }
    return NULL;
}


static void emit_finding(const wchar_t *key_path, const wchar_t *value_name, DWORD value_type,
                         const BYTE *data, DWORD data_size, const policy_whitelist_entry *entry,
                         scan_counters *counters) {
    char path_utf8[MAX_KEY_PATH];
    char value_utf8[MAX_VALUE_NAME];
    char data_utf8[MAX_DATA_STRING];
    char number_buf[64];
    wchar_t rooted_path[MAX_KEY_PATH];
    const char *type_name = registry_type_name(value_type);

    inline_memset(path_utf8, 0, sizeof(path_utf8));
    inline_memset(value_utf8, 0, sizeof(value_utf8));
    inline_memset(data_utf8, 0, sizeof(data_utf8));
    inline_memset(number_buf, 0, sizeof(number_buf));
    inline_memset(rooted_path, 0, sizeof(rooted_path));

    build_rooted_path(key_path, rooted_path, MAX_KEY_PATH);
    wide_to_utf8(rooted_path, path_utf8, sizeof(path_utf8));
    wide_to_utf8(value_name, value_utf8, sizeof(value_utf8));

    if (value_type == REG_DWORD && data_size >= sizeof(DWORD)) {
        u64_to_string((unsigned long long)(*((DWORD *)data)), number_buf, sizeof(number_buf));
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] %s: %s\n",
            entry->meaning, number_buf);
        BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\%s (Type: %s)\n", path_utf8, value_utf8, type_name);
    } else if (value_type == REG_QWORD && data_size >= sizeof(unsigned long long)) {
        u64_to_string(*((unsigned long long *)data), number_buf, sizeof(number_buf));
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] %s: %s\n",
            entry->meaning, number_buf);
        BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\%s (Type: %s)\n", path_utf8, value_utf8, type_name);
    } else if (value_type == REG_SZ || value_type == REG_EXPAND_SZ) {
        wide_to_utf8_len((const wchar_t *)data, data_size, data_utf8, sizeof(data_utf8));
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] %s: %s\n",
            entry->meaning, data_utf8);
        BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\%s (Type: %s)\n", path_utf8, value_utf8, type_name);
    } else if (value_type == REG_MULTI_SZ) {
        multi_sz_to_utf8_bounded((const wchar_t *)data, data_size, data_utf8, sizeof(data_utf8));
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] %s: %s\n",
            entry->meaning, data_utf8);
        BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\%s (Type: %s)\n", path_utf8, value_utf8, type_name);
    } else if (value_type == REG_BINARY) {
        binary_to_hex(data, data_size, data_utf8, sizeof(data_utf8));
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] %s: %s\n",
            entry->meaning, data_utf8);
        BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\%s (Type: %s)\n", path_utf8, value_utf8, type_name);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] %s: <unhandled type>\n",
            entry->meaning);
        BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\%s (Type: %s)\n", path_utf8, value_utf8, type_name);
    }

    counters->values_printed++;
}


static void check_dsregcmd_equivalent(scan_counters *counters) {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    wchar_t subkey_name[MAX_VALUE_NAME];
    DWORD subkey_size;
    int found_join = 0;
    char path_utf8[MAX_KEY_PATH];
    char value_utf8[MAX_VALUE_NAME];
    char data_utf8[MAX_DATA_STRING];
    
    result = ADVAPI32$RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        return;
    }
    
    
    while (1) {
        subkey_size = MAX_VALUE_NAME;
        inline_memset(subkey_name, 0, sizeof(subkey_name));
        result = ADVAPI32$RegEnumKeyExW(hKey, index, subkey_name, &subkey_size, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        
        HKEY hJoinKey;
        wchar_t join_path[MAX_KEY_PATH];
        build_subkey_path(L"SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo", subkey_name, join_path, MAX_KEY_PATH);
        
        result = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, join_path, 0, KEY_READ, &hJoinKey);
        if (result == ERROR_SUCCESS) {
            
            DWORD value_type;
            BYTE data[MAX_VALUE_DATA];
            DWORD data_size = sizeof(data);
            inline_memset(data, 0, sizeof(data));
            
            result = ADVAPI32$RegQueryValueExW(hJoinKey, L"TenantId", NULL, &value_type, data, &data_size);
            if (result == ERROR_SUCCESS && (value_type == REG_SZ || value_type == REG_EXPAND_SZ)) {
                found_join = 1;
                build_rooted_path(join_path, join_path, MAX_KEY_PATH);
                wide_to_utf8(join_path, path_utf8, sizeof(path_utf8));
                wide_to_utf8_len((const wchar_t *)data, data_size, data_utf8, sizeof(data_utf8));
                
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Indicator: dsregcmd /status equivalent\n");
                BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\TenantId\n", path_utf8);
                BeaconPrintf(CALLBACK_OUTPUT, "    Value: %s\n", data_utf8);
                BeaconPrintf(CALLBACK_OUTPUT, "    Score: +3\n");
                counters->score.join_state_mdm_url = 3;
            }
            
            
            data_size = sizeof(data);
            inline_memset(data, 0, sizeof(data));
            result = ADVAPI32$RegQueryValueExW(hJoinKey, L"MdmUrl", NULL, &value_type, data, &data_size);
            if (result == ERROR_SUCCESS && (value_type == REG_SZ || value_type == REG_EXPAND_SZ)) {
                wide_to_utf8_len((const wchar_t *)data, data_size, data_utf8, sizeof(data_utf8));
                BeaconPrintf(CALLBACK_OUTPUT, "    MDM URL: %s\n", data_utf8);
            }
            
            ADVAPI32$RegCloseKey(hJoinKey);
        }
        
        index++;
    }
    
    ADVAPI32$RegCloseKey(hKey);
    
    
    result = ADVAPI32$RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CDJ\\AAD",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result == ERROR_SUCCESS) {
        DWORD value_type;
        BYTE data[MAX_VALUE_DATA];
        DWORD data_size = sizeof(data);
        inline_memset(data, 0, sizeof(data));
        
        result = ADVAPI32$RegQueryValueExW(hKey, L"TenantId", NULL, &value_type, data, &data_size);
        if (result == ERROR_SUCCESS && (value_type == REG_SZ || value_type == REG_EXPAND_SZ) && !found_join) {
            found_join = 1;
            wide_to_utf8(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CDJ\\AAD", path_utf8, sizeof(path_utf8));
            wide_to_utf8_len((const wchar_t *)data, data_size, data_utf8, sizeof(data_utf8));
            
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Indicator: dsregcmd /status equivalent\n");
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\TenantId\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    Value: %s\n", data_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    Score: +3\n");
            counters->score.join_state_mdm_url = 3;
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
}


static void check_mdm_config_policy(scan_counters *counters) {
    HKEY hKey;
    LONG result;
    DWORD value_type;
    BYTE data[MAX_VALUE_DATA];
    DWORD data_size = sizeof(data);
    char path_utf8[MAX_KEY_PATH];
    char number_buf[64];
    
    result = ADVAPI32$RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\MDM",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        return;
    }
    
    inline_memset(data, 0, sizeof(data));
    result = ADVAPI32$RegQueryValueExW(hKey, L"AutoEnrollMDM", NULL, &value_type, data, &data_size);
    if (result == ERROR_SUCCESS && value_type == REG_DWORD && data_size >= sizeof(DWORD)) {
        DWORD value = *((DWORD *)data);
        if (value != 0) {
            wide_to_utf8(L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\MDM", path_utf8, sizeof(path_utf8));
            u64_to_string((unsigned long long)value, number_buf, sizeof(number_buf));
            
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Indicator: MDM configuration policy\n");
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\AutoEnrollMDM\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    Value: %s\n", number_buf);
            BeaconPrintf(CALLBACK_OUTPUT, "    Score: +2\n");
            counters->score.mdm_config_policy = 2;
        }
    }
    
    ADVAPI32$RegCloseKey(hKey);
}


static void check_intune_evidence(scan_counters *counters) {
    HKEY hKey;
    LONG result;
    DWORD value_type;
    BYTE data[MAX_VALUE_DATA];
    DWORD data_size = sizeof(data);
    char path_utf8[MAX_KEY_PATH];
    char data_utf8[MAX_DATA_STRING];
    
   
    result = ADVAPI32$RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MDM",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result == ERROR_SUCCESS) {
        inline_memset(data, 0, sizeof(data));
        data_size = sizeof(data);
        result = ADVAPI32$RegQueryValueExW(hKey, L"MDMDeviceID", NULL, &value_type, data, &data_size);
        if (result == ERROR_SUCCESS && (value_type == REG_SZ || value_type == REG_EXPAND_SZ)) {
            wide_to_utf8(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MDM", path_utf8, sizeof(path_utf8));
            wide_to_utf8_len((const wchar_t *)data, data_size, data_utf8, sizeof(data_utf8));
            
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Indicator: Intune enrollment evidence\n");
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\MDMDeviceID\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    Value: %s\n", data_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    Score: +2\n");
            counters->score.intune_evidence = 2;
        }
        
        ADVAPI32$RegCloseKey(hKey);
    }
}


static HRESULT initialize_com_security(void) {
    HRESULT hr = OLE32$CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    return hr;
}

static void enumerate_enterprisemgmt_tasks(scan_counters *counters) {
    HRESULT hr;
    ITaskService *pService = NULL;
    ITaskFolder *pRootFolder = NULL;
    ITaskFolder *pEnterpriseMgmtFolder = NULL;
    IRegisteredTaskCollection *pTaskCollection = NULL;
    BSTR folderPath = NULL;
    VARIANT vEmpty;
    LONG taskCount = 0;
    VARIANT vIndex;
    char pathBuffer[512];
    char nameBuffer[256];
    wchar_t guid_from_path[MAX_GUID_STRING];
    
    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && (unsigned long)hr != 0x80010106UL) { 
        return;
    }
    
    initialize_com_security();
    
    hr = OLE32$CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void**)&pService);
    if (FAILED(hr) || pService == NULL) {
        OLE32$CoUninitialize();
        return;
    }
    
    OLEAUT32$VariantInit(&vEmpty);
    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr)) {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        OLE32$CoUninitialize();
        return;
    }
    
    
    folderPath = OLEAUT32$SysAllocString(L"\\Microsoft\\Windows\\EnterpriseMgmt");
    if (folderPath != NULL) {
        hr = pService->lpVtbl->GetFolder(pService, folderPath, &pEnterpriseMgmtFolder);
        OLEAUT32$SysFreeString(folderPath);
        
        if (SUCCEEDED(hr) && pEnterpriseMgmtFolder != NULL) {
            hr = pEnterpriseMgmtFolder->lpVtbl->GetTasks(pEnterpriseMgmtFolder, TASK_ENUM_HIDDEN, &pTaskCollection);
            if (SUCCEEDED(hr) && pTaskCollection != NULL) {
                hr = pTaskCollection->lpVtbl->get_Count(pTaskCollection, &taskCount);
                if (SUCCEEDED(hr) && taskCount > 0) {
                    OLEAUT32$VariantInit(&vIndex);
                    vIndex.vt = VT_I4;
                    
                    for (LONG i = 1; i <= taskCount && i <= 50; i++) {
                        IRegisteredTask *pTask = NULL;
                        BSTR taskPath = NULL;
                        
                        vIndex.lVal = i;
                        hr = pTaskCollection->lpVtbl->get_Item(pTaskCollection, vIndex, &pTask);
                        if (FAILED(hr) || pTask == NULL) continue;
                        
                        hr = pTask->lpVtbl->get_Path(pTask, &taskPath);
                        if (SUCCEEDED(hr) && taskPath != NULL) {
                            
                            if (wcs_prefix_ci((const wchar_t *)taskPath, L"\\Microsoft\\Windows\\EnterpriseMgmt\\")) {
                                const wchar_t *guid_start = (const wchar_t *)taskPath + 35; // Length of prefix
                                inline_memset(pathBuffer, 0, sizeof(pathBuffer));
                                wide_to_utf8((const wchar_t *)taskPath, pathBuffer, sizeof(pathBuffer));
                                size_t guid_len = 0;
                                while (guid_start[guid_len] && guid_start[guid_len] != L'\\' && guid_len < MAX_GUID_STRING - 1) {
                                    guid_from_path[guid_len] = guid_start[guid_len];
                                    guid_len++;
                                }
                                guid_from_path[guid_len] = L'\0';
                                
                                if (guid_len > 0 && guid_from_path[0] == L'{') {
                                    enrollment_guid_t *guid_entry = find_or_add_enrollment_guid(counters, guid_from_path);
                                    if (guid_entry) {
                                        guid_entry->found_in_tasks = 1;
                                    }
                                    
                                    if (!counters->score.enterprisemgmt_tasks) {
                                        char guid_utf8[MAX_GUID_STRING];
                                        inline_memset(guid_utf8, 0, sizeof(guid_utf8));
                                        wide_to_utf8(guid_from_path, guid_utf8, sizeof(guid_utf8));
                                        
                                        BeaconPrintf(CALLBACK_OUTPUT, "[+] Indicator: EnterpriseMgmt scheduled task\n");
                                        BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: Task: %s\n", pathBuffer);
                                        BeaconPrintf(CALLBACK_OUTPUT, "    Enrollment GUID: %s\n", guid_utf8);
                                        BeaconPrintf(CALLBACK_OUTPUT, "    Score: +2\n");
                                        counters->score.enterprisemgmt_tasks = 2;
                                    }
                                }
                            }
                            
                            OLEAUT32$SysFreeString(taskPath);
                        }
                        
                        ((IUnknown *)pTask)->lpVtbl->Release((IUnknown *)pTask);
                    }
                    
                    OLEAUT32$VariantClear(&vIndex);
                }
                ((IUnknown *)pTaskCollection)->lpVtbl->Release((IUnknown *)pTaskCollection);
            }
            ((IUnknown *)pEnterpriseMgmtFolder)->lpVtbl->Release((IUnknown *)pEnterpriseMgmtFolder);
        }
    }
    
    ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
    OLE32$CoUninitialize();
}

static int is_enrollment_path(const wchar_t *path) {
    return wcs_prefix_ci(path, L"SOFTWARE\\Microsoft\\Enrollments") &&
           !wcs_equal_ci(path, L"SOFTWARE\\Microsoft\\Enrollments");
}

static int is_meaningful_enrollment(DWORD enrollment_type, int has_device_id, int has_tenant_id, int has_provider, int has_discovery_url) {
    if (enrollment_type == 0) {
        return 0;
    }
    if (!has_tenant_id && !has_provider && !has_discovery_url) {
        return 0;
    }
    return 1;
}


static void emit_enrollment_grouped(const wchar_t *key_path, HKEY hKey, scan_counters *counters) {
    char path_utf8[MAX_KEY_PATH];
    wchar_t rooted_path[MAX_KEY_PATH];
    DWORD enrollment_state = 0;
    DWORD enrollment_type = 0;
    wchar_t aad_device_id[MAX_VALUE_DATA / sizeof(wchar_t)] = {0};
    wchar_t tenant_id[MAX_VALUE_DATA / sizeof(wchar_t)] = {0};
    wchar_t provider_id[MAX_VALUE_DATA / sizeof(wchar_t)] = {0};
    wchar_t discovery_url[MAX_VALUE_DATA / sizeof(wchar_t)] = {0};
    wchar_t enrollment_guid[MAX_GUID_STRING] = {0};
    int has_state = 0, has_type = 0, has_device_id = 0, has_tenant_id = 0;
    int has_provider = 0, has_discovery_url = 0;
    DWORD value_type;
    DWORD data_size;
    LONG result;

    build_rooted_path(key_path, rooted_path, MAX_KEY_PATH);
    wide_to_utf8(rooted_path, path_utf8, sizeof(path_utf8));
    

    extract_guid_from_path(key_path, enrollment_guid, MAX_GUID_STRING);
    enrollment_guid_t *guid_entry = NULL;
    if (enrollment_guid[0]) {
        guid_entry = find_or_add_enrollment_guid(counters, enrollment_guid);
        if (guid_entry) {
            guid_entry->found_in_enrollments = 1;
        }
    }

   
    DWORD index = 0;
    while (1) {
        wchar_t value_name[MAX_VALUE_NAME];
        DWORD value_name_size = MAX_VALUE_NAME;
        inline_memset(value_name, 0, sizeof(value_name));

        result = ADVAPI32$RegEnumValueW(hKey, index, value_name, &value_name_size, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }

        data_size = MAX_VALUE_DATA;
        BYTE data[MAX_VALUE_DATA];
        inline_memset(data, 0, sizeof(data));
        result = ADVAPI32$RegQueryValueExW(hKey, value_name, NULL, &value_type, data, &data_size);
        
        if (result == ERROR_SUCCESS) {
            const policy_whitelist_entry *entry = find_whitelist_match(key_path, value_name);
            if (entry) {
                counters->matches++;
                if (wcs_equal_ci(value_name, L"EnrollmentState") && value_type == REG_DWORD && data_size >= sizeof(DWORD)) {
                    enrollment_state = *((DWORD *)data);
                    has_state = 1;
                } else if (wcs_equal_ci(value_name, L"EnrollmentType") && value_type == REG_DWORD && data_size >= sizeof(DWORD)) {
                    enrollment_type = *((DWORD *)data);
                    has_type = 1;
                } else if (wcs_equal_ci(value_name, L"AADDeviceID") && (value_type == REG_SZ || value_type == REG_EXPAND_SZ)) {
                    size_t copy_size = data_size < sizeof(aad_device_id) ? data_size : sizeof(aad_device_id) - sizeof(wchar_t);
                    inline_memcpy(aad_device_id, data, copy_size);
                    aad_device_id[copy_size / sizeof(wchar_t)] = L'\0';
                    has_device_id = 1;
                } else if (wcs_equal_ci(value_name, L"TenantID") && (value_type == REG_SZ || value_type == REG_EXPAND_SZ)) {
                    size_t copy_size = data_size < sizeof(tenant_id) ? data_size : sizeof(tenant_id) - sizeof(wchar_t);
                    inline_memcpy(tenant_id, data, copy_size);
                    tenant_id[copy_size / sizeof(wchar_t)] = L'\0';
                    has_tenant_id = 1;
                }
            }
            
            
            if (wcs_equal_ci(value_name, L"ProviderID") && (value_type == REG_SZ || value_type == REG_EXPAND_SZ)) {
                size_t copy_size = data_size < sizeof(provider_id) ? data_size : sizeof(provider_id) - sizeof(wchar_t);
                inline_memcpy(provider_id, data, copy_size);
                provider_id[copy_size / sizeof(wchar_t)] = L'\0';
                has_provider = 1;
            } else if (wcs_equal_ci(value_name, L"DiscoveryServiceFullURL") && (value_type == REG_SZ || value_type == REG_EXPAND_SZ)) {
                size_t copy_size = data_size < sizeof(discovery_url) ? data_size : sizeof(discovery_url) - sizeof(wchar_t);
                inline_memcpy(discovery_url, data, copy_size);
                discovery_url[copy_size / sizeof(wchar_t)] = L'\0';
                has_discovery_url = 1;
            }
        }
        
        index++;
    }

    
    if ((has_state || has_type || has_device_id || has_tenant_id) &&
        is_meaningful_enrollment(enrollment_type, has_device_id, has_tenant_id, has_provider, has_discovery_url)) {
        char number_buf[64];
        char device_id_utf8[MAX_DATA_STRING];
        char tenant_id_utf8[MAX_DATA_STRING];
        char provider_id_utf8[MAX_DATA_STRING];
        char discovery_url_utf8[MAX_DATA_STRING];
        char guid_utf8[MAX_GUID_STRING];
        
        inline_memset(number_buf, 0, sizeof(number_buf));
        inline_memset(device_id_utf8, 0, sizeof(device_id_utf8));
        inline_memset(tenant_id_utf8, 0, sizeof(tenant_id_utf8));
        inline_memset(provider_id_utf8, 0, sizeof(provider_id_utf8));
        inline_memset(discovery_url_utf8, 0, sizeof(discovery_url_utf8));
        inline_memset(guid_utf8, 0, sizeof(guid_utf8));
        
        wide_to_utf8(enrollment_guid, guid_utf8, sizeof(guid_utf8));

        BeaconPrintf(CALLBACK_OUTPUT, "[+] MDM Enrollment Group (GUID: %s)\n", guid_utf8[0] ? guid_utf8 : "(unknown)");
        if (has_state) {
            u64_to_string((unsigned long long)enrollment_state, number_buf, sizeof(number_buf));
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\EnrollmentState\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    EnrollmentState: %s\n", number_buf);
        }
        if (has_type) {
            u64_to_string((unsigned long long)enrollment_type, number_buf, sizeof(number_buf));
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\EnrollmentType\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    EnrollmentType: %s\n", number_buf);
        }
        if (has_device_id) {
            wide_to_utf8(aad_device_id, device_id_utf8, sizeof(device_id_utf8));
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\AADDeviceID\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    AADDeviceID: %s\n", device_id_utf8);
        }
        if (has_tenant_id) {
            wide_to_utf8(tenant_id, tenant_id_utf8, sizeof(tenant_id_utf8));
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\TenantID\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    TenantID: %s\n", tenant_id_utf8);
        }
        if (has_provider) {
            wide_to_utf8(provider_id, provider_id_utf8, sizeof(provider_id_utf8));
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\ProviderID\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    ProviderID: %s\n", provider_id_utf8);
        }
        if (has_discovery_url) {
            wide_to_utf8(discovery_url, discovery_url_utf8, sizeof(discovery_url_utf8));
            BeaconPrintf(CALLBACK_OUTPUT, "    Provenance: %s\\DiscoveryServiceFullURL\n", path_utf8);
            BeaconPrintf(CALLBACK_OUTPUT, "    DiscoveryServiceFullURL: %s\n", discovery_url_utf8);
        }
        
        
        if (guid_entry && guid_entry->found_in_tracked) {
            BeaconPrintf(CALLBACK_OUTPUT, "    [Correlated from EnterpriseResourceManager\\Tracked\\%s]\n", guid_utf8);
        }
        
        
        if (guid_entry && guid_entry->found_in_providers) {
            BeaconPrintf(CALLBACK_OUTPUT, "    [Correlated from PolicyManager\\providers\\%s]\n", guid_utf8);
        }
        
        counters->values_printed++;
        counters->score.enrollments_registry = 1;
    }
}

static void enumerate_values(HKEY hKey, const wchar_t *key_path, scan_counters *counters) {
    
    if (is_enrollment_path(key_path)) {
        emit_enrollment_grouped(key_path, hKey, counters);
        return;
    }

    
    DWORD index = 0;
    LONG result;
    wchar_t value_name[MAX_VALUE_NAME];
    DWORD value_name_size;

    while (1) {
        value_name_size = MAX_VALUE_NAME;
        inline_memset(value_name, 0, sizeof(value_name));

        result = ADVAPI32$RegEnumValueW(hKey, index, value_name, &value_name_size, NULL, NULL, NULL, NULL);

        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }

        const policy_whitelist_entry *entry = find_whitelist_match(key_path, value_name);
        if (entry) {
            DWORD value_type = 0;
            BYTE data[MAX_VALUE_DATA];
            DWORD data_size = sizeof(data);
            inline_memset(data, 0, sizeof(data));

            counters->matches++;
            result = ADVAPI32$RegQueryValueExW(hKey, value_name, NULL, &value_type, data, &data_size);
            if (result == ERROR_SUCCESS) {
                emit_finding(key_path, value_name, value_type, data, data_size, entry, counters);
            }
        }

        index++;
    }
}


static void enumerate_registry_tree(HKEY root, const wchar_t *base_path, int depth, scan_counters *counters) {
    HKEY hKey;
    LONG result;
    DWORD index = 0;
    wchar_t subkey_name[MAX_VALUE_NAME];
    DWORD subkey_size;

    result = ADVAPI32$RegOpenKeyExW(root, base_path, 0, KEY_READ, &hKey);
    if (result == ERROR_ACCESS_DENIED) {
        counters->access_denied++;
        return;
    }
    if (result != ERROR_SUCCESS) {
        return;
    }

    enumerate_values(hKey, base_path, counters);

    if (depth <= 0) {
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    while (1) {
        subkey_size = MAX_VALUE_NAME;
        inline_memset(subkey_name, 0, sizeof(subkey_name));
        result = ADVAPI32$RegEnumKeyExW(hKey, index, subkey_name, &subkey_size, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (result != ERROR_SUCCESS) {
            index++;
            continue;
        }
        counters->subkeys_scanned++;
        
        
        if (wcs_prefix_ci(base_path, L"SOFTWARE\\Microsoft\\EnterpriseResourceManager\\Tracked")) {
            enrollment_guid_t *guid_entry = find_or_add_enrollment_guid(counters, subkey_name);
            if (guid_entry) {
                guid_entry->found_in_tracked = 1;
            }
        } else if (wcs_prefix_ci(base_path, L"SOFTWARE\\Microsoft\\PolicyManager\\providers")) {
            enrollment_guid_t *guid_entry = find_or_add_enrollment_guid(counters, subkey_name);
            if (guid_entry) {
                guid_entry->found_in_providers = 1;
            }
        }
        
        {
            wchar_t next_path[MAX_KEY_PATH];
            if (build_subkey_path(base_path, subkey_name, next_path, MAX_KEY_PATH)) {
                enumerate_registry_tree(root, next_path, depth - 1, counters);
            }
        }
        index++;
    }

    ADVAPI32$RegCloseKey(hKey);
}


static void emit_posture_verdict(scan_counters *counters) {
    counters->score.total_score = 
        counters->score.join_state_mdm_url +
        counters->score.enterprisemgmt_tasks +
        counters->score.mdm_config_policy +
        counters->score.intune_evidence +
        counters->score.enrollments_registry;
    
    const char *posture;
    if (counters->score.total_score >= 7) {
        posture = "Enrolled";
    } else if (counters->score.total_score >= 4) {
        posture = "Partially enrolled";
    } else {
        posture = "Not enrolled";
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Posture Verdict\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    MDM posture: %s\n", posture);
    BeaconPrintf(CALLBACK_OUTPUT, "    Score: %d/10\n", counters->score.total_score);
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;

    scan_counters counters;
    inline_memset(&counters, 0, sizeof(counters));

    
    check_dsregcmd_equivalent(&counters);
    check_mdm_config_policy(&counters);
    check_intune_evidence(&counters);
    enumerate_enterprisemgmt_tasks(&counters);

    /
    enumerate_registry_tree(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\PolicyManager\\current\\device",
        2,
        &counters
    );

    enumerate_registry_tree(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        1,
        &counters
    );

    enumerate_registry_tree(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication",
        1,
        &counters
    );

    enumerate_registry_tree(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Enrollments",
        3,
        &counters
    );

    enumerate_registry_tree(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\PolicyManager\\providers",
        3,
        &counters
    );

    enumerate_registry_tree(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\EnterpriseResourceManager\\Tracked",
        3,
        &counters
    );

    enumerate_registry_tree(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MDM",
        2,
        &counters
    );

    
    emit_posture_verdict(&counters);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[i] Summary: scanned %lu subkeys, found %lu matches, printed %lu values",
        (unsigned long)counters.subkeys_scanned,
        (unsigned long)counters.matches,
        (unsigned long)counters.values_printed);
    if (counters.access_denied > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, ", %lu access denied", (unsigned long)counters.access_denied);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
}
