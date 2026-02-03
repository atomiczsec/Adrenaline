#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "beacon.h"


static const IID IID_IUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

#ifndef STDMETHODCALLTYPE
#define STDMETHODCALLTYPE __stdcall
#endif
#ifndef CONST_VTBL
#define CONST_VTBL
#endif

#ifndef LPOLESTR
typedef wchar_t OLECHAR;
typedef OLECHAR *LPOLESTR;
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

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString(LPOLESTR lpsz, LPCLSID pclsid);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPOLESTR lpsz, LPIID lpiid);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT VOID WINAPI OLE32$CoUninitialize(VOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);

DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

#ifndef COINIT_APARTMENTTHREADED
#define COINIT_APARTMENTTHREADED 0x2
#endif

#ifndef CLSCTX_INPROC_SERVER
#define CLSCTX_INPROC_SERVER 0x1
#endif

#ifndef CLSCTX_LOCAL_SERVER
#define CLSCTX_LOCAL_SERVER 0x4
#endif

#ifndef S_OK
#define S_OK ((HRESULT)0x00000000L)
#endif

#ifndef RPC_E_CHANGED_MODE
#define RPC_E_CHANGED_MODE ((HRESULT)0x80010106L)
#endif

typedef struct {
    HRESULT value;
    const char *name;
} hresult_entry;

static const hresult_entry hresult_table[] = {
    {S_OK, "S_OK"},
    {RPC_E_CHANGED_MODE, "RPC_E_CHANGED_MODE"},
    {0x80040154L, "CLASS_E_CLASSNOTAVAILABLE"},
    {0x80070005L, "E_ACCESSDENIED"},
    {0x80080005L, "CO_E_SERVER_EXEC_FAILURE"},
    {0x800706BAL, "RPC_S_SERVER_UNAVAILABLE"},
};

static void format_hex_ulong(char *buf, int buf_size, unsigned long val) {
    const char *hex = "0123456789abcdef";
    int i = 0;
    
    if (buf_size < 11) {
        if (buf_size > 0) buf[0] = '\0';
        return;
    }
    
    buf[i++] = '0';
    buf[i++] = 'x';
    
    for (int shift = 28; shift >= 0; shift -= 4) {
        if (i < buf_size - 1) {
            buf[i++] = hex[(val >> shift) & 0xF];
        }
    }
    buf[i] = '\0';
}

static void format_hresult_with_name(char *buf, int buf_size, const char *name, unsigned long hr) {
    int i = 0;
    const char *p = name;
    
    
    while (*p && i < buf_size - 1) {
        buf[i++] = *p++;
    }
    
    
    if (i < buf_size - 1) buf[i++] = ' ';
    if (i < buf_size - 1) buf[i++] = '(';
    
    
    if (i + 10 < buf_size - 1) {
        format_hex_ulong(buf + i, buf_size - i, hr);
        i += 10;  
    }
    
    
    if (i < buf_size - 1) buf[i++] = ')';
    buf[i] = '\0';
}

static const char* format_hresult(HRESULT hr, char *buffer, int buffer_len) {
    const char *name = NULL;

    for (int i = 0; i < (int)(sizeof(hresult_table) / sizeof(hresult_table[0])); i++) {
        if (hresult_table[i].value == hr) {
            name = hresult_table[i].name;
            break;
        }
    }

    if (name != NULL) {
        format_hresult_with_name(buffer, buffer_len, name, (unsigned long)hr);
    } else {
        format_hex_ulong(buffer, buffer_len, (unsigned long)hr);
    }

    return buffer;
}

static int ansi_to_wide(const char *src, int src_len, wchar_t *dst, int dst_size) {
    int converted = 0;

    if (src_len <= 0 || dst_size <= 0) {
        return 0;
    }

    converted = KERNEL32$MultiByteToWideChar(CP_ACP, 0, src, src_len, dst, dst_size);

    if (converted > 0) {
        if (converted < dst_size) {
            dst[converted] = L'\0';
        } else {
            dst[dst_size - 1] = L'\0';
        }
    }

    return converted;
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    char *guidStr = NULL;
    char *iidStr = NULL;
    char guidBuf[256] = {0};
    char iidBuf[256] = {0};
    int guidLen = 0;
    int iidLen = 0;
    wchar_t guidWide[39] = {0};
    wchar_t iidWide[39] = {0};
    CLSID clsid = {0};
    IID iid = IID_IUnknown;
    const char *iidDisplay = "IID_IUnknown (default)";
    BOOL useDefaultIID = TRUE;
    IUnknown *pUnknown = NULL;
    HRESULT hr;
    BOOL comInitialized = FALSE;
    char hrBuf[64] = {0};

    BeaconDataParse(&parser, args, (int)alen);

    if (BeaconDataLength(&parser) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Usage: com_probe <GUID> [IID]\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Example: com_probe {AEB5B82E-51E7-41EA-9A0B-3D2C8BEDE7B4}\n");
        return;
    }

    guidStr = BeaconDataExtract(&parser, &guidLen);
    if (!guidStr || guidLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Usage: com_probe <GUID> [IID]\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Example: com_probe {AEB5B82E-51E7-41EA-9A0B-3D2C8BEDE7B4}\n");
        return;
    }

    if (guidLen >= (int)sizeof(guidWide) / (int)sizeof(wchar_t)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GUID string is too long\n");
        return;
    }

    for (int i = 0; i < guidLen; i++) {
        guidBuf[i] = guidStr[i];
    }
    guidBuf[guidLen] = '\0';

    if (guidBuf[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[-] Usage: com_probe <GUID> [IID]\n");
        return;
    }

    if (ansi_to_wide(guidBuf, guidLen, guidWide, sizeof(guidWide) / sizeof(wchar_t)) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert GUID string to wide string\n");
        return;
    }

    if (BeaconDataLength(&parser) > 0) {
        iidStr = BeaconDataExtract(&parser, &iidLen);
        if (iidStr && iidLen > 0) {
            if (iidLen >= (int)sizeof(iidWide) / (int)sizeof(wchar_t)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] IID string is too long\n");
                return;
            }

            for (int i = 0; i < iidLen; i++) {
                iidBuf[i] = iidStr[i];
            }
            iidBuf[iidLen] = '\0';

            if (ansi_to_wide(iidBuf, iidLen, iidWide, sizeof(iidWide) / sizeof(wchar_t)) == 0) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert IID string to wide string\n");
                return;
            }

            hr = OLE32$IIDFromString(iidWide, &iid);
            if (FAILED(hr)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] IIDFromString failed (HRESULT: %s)\n", format_hresult(hr, hrBuf, sizeof(hrBuf)));
                return;
            }

            iidDisplay = iidBuf;
            useDefaultIID = FALSE;
        }
    }

    hr = OLE32$CLSIDFromString(guidWide, &clsid);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CLSIDFromString failed (HRESULT: %s)\n", format_hresult(hr, hrBuf, sizeof(hrBuf)));
        return;
    }

    if (useDefaultIID) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Using default IID_IUnknown\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Probing CLSID: %s with IID: %s\n", guidBuf, iidDisplay);

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        if (hr != RPC_E_CHANGED_MODE) {
            BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx failed (HRESULT: %s)\n", format_hresult(hr, hrBuf, sizeof(hrBuf)));
            return;
        }
    } else {
        comInitialized = TRUE;
        BeaconPrintf(CALLBACK_OUTPUT, "[i] COM initialized successfully (COINIT_APARTMENTTHREADED)\n");
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Attempting CLSCTX_INPROC_SERVER activation...\n");
    hr = OLE32$CoCreateInstance(
        &clsid,
        NULL,
        CLSCTX_INPROC_SERVER,
        &iid,
        (void**)&pUnknown
    );

    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] In-proc activation succeeded (HRESULT: %s)\n", format_hresult(hr, hrBuf, sizeof(hrBuf)));

        if (pUnknown != NULL) {
            pUnknown->lpVtbl->Release(pUnknown);
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Object released cleanly after in-proc activation\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] In-proc activation failed (HRESULT: %s)\n", format_hresult(hr, hrBuf, sizeof(hrBuf)));
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Falling back to CLSCTX_LOCAL_SERVER...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Attempting CLSCTX_LOCAL_SERVER activation...\n");

        hr = OLE32$CoCreateInstance(
            &clsid,
            NULL,
            CLSCTX_LOCAL_SERVER,
            &iid,
            (void**)&pUnknown
        );

        if (SUCCEEDED(hr)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Local server activation succeeded (HRESULT: %s)\n", format_hresult(hr, hrBuf, sizeof(hrBuf)));

            if (pUnknown != NULL) {
                pUnknown->lpVtbl->Release(pUnknown);
                BeaconPrintf(CALLBACK_OUTPUT, "[i] Object released cleanly after local server activation\n");
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Local server activation failed (HRESULT: %s)\n", format_hresult(hr, hrBuf, sizeof(hrBuf)));
        }
    }
    
    if (comInitialized) {
        OLE32$CoUninitialize();
    }
}

