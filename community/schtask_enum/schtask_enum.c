#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <taskschd.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

const CLSID CLSID_TaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
const IID IID_ITaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};


DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT VOID WINAPI OLE32$CoUninitialize(VOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT VOID WINAPI OLEAUT32$VariantInit(VARIANT*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANT*);
DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT VOID WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VarFormatDateTime(VARIANT*, int, int, BSTR*);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif


#ifndef S_OK
#define S_OK ((HRESULT)0x00000000L)
#endif
#ifndef S_FALSE
#define S_FALSE ((HRESULT)0x00000001L)
#endif
#ifndef E_NOINTERFACE
#define E_NOINTERFACE ((HRESULT)0x80004002L)
#endif
#ifndef E_CLASS_NOT_REGISTERED
#define E_CLASS_NOT_REGISTERED ((HRESULT)0x80040154L)
#endif
#ifndef CO_E_SERVER_EXEC_FAILURE
#define CO_E_SERVER_EXEC_FAILURE ((HRESULT)0x80080005L)
#endif
#ifndef RPC_E_CHANGED_MODE
#define RPC_E_CHANGED_MODE ((HRESULT)0x80010106L)
#endif
#ifndef CO_E_NOTINITIALIZED
#define CO_E_NOTINITIALIZED ((HRESULT)0x800401F0L)
#endif
#ifndef RPC_E_TOO_LATE
#define RPC_E_TOO_LATE ((HRESULT)0x80010119L)
#endif
#ifndef RPC_C_AUTHN_LEVEL_NONE
#define RPC_C_AUTHN_LEVEL_NONE 0
#endif
#ifndef RPC_C_AUTHN_LEVEL_DEFAULT
#define RPC_C_AUTHN_LEVEL_DEFAULT 0
#endif
#ifndef RPC_C_AUTHN_LEVEL_PKT_PRIVACY
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY 6
#endif
#ifndef RPC_C_AUTHN_LEVEL_CONNECT
#define RPC_C_AUTHN_LEVEL_CONNECT 2
#endif
#ifndef RPC_C_IMP_LEVEL_IMPERSONATE
#define RPC_C_IMP_LEVEL_IMPERSONATE 3
#endif
#ifndef EOAC_NONE
#define EOAC_NONE 0
#endif
#ifndef CLSCTX_ALL
#define CLSCTX_ALL (CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)
#endif
#ifndef CLSCTX_INPROC_HANDLER
#define CLSCTX_INPROC_HANDLER 0x2
#endif
#ifndef CLSCTX_INPROC_SERVER
#define CLSCTX_INPROC_SERVER 0x1
#endif
#ifndef CLSCTX_LOCAL_SERVER
#define CLSCTX_LOCAL_SERVER 0x4
#endif
#ifndef CLSCTX_REMOTE_SERVER
#define CLSCTX_REMOTE_SERVER 0x10
#endif
#ifndef COINIT_APARTMENTTHREADED
#define COINIT_APARTMENTTHREADED 0x2
#endif

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static int wide_to_utf8(LPCWSTR src, char *dst, int dstSize) {
    if (dst == NULL || dstSize <= 0) return 0;
    if (src == NULL) {
        dst[0] = '\0';
        return 1;
    }
    
    int result = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstSize, NULL, NULL);
    if (result == 0) {
        int i = 0;
        while (src[i] != L'\0' && i < (dstSize - 1)) {
            dst[i] = (char)(src[i] & 0xFF);
            i++;
        }
        dst[i] = '\0';
        result = i + 1;
    }
    return result;
}

static int utf8_to_wide(const char *src, wchar_t *dst, int dstCount) {
    if (dst == NULL || dstCount <= 0) return 0;
    if (src == NULL) {
        dst[0] = L'\0';
        return 1;
    }

    int result = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dstCount);
    if (result == 0) {
        int i = 0;
        while (src[i] != '\0' && i < (dstCount - 1)) {
            dst[i] = (wchar_t)(unsigned char)src[i];
            i++;
        }
        dst[i] = L'\0';
        result = i + 1;
    }
    return result;
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

    if (hr == RPC_E_TOO_LATE) {
        return S_OK;
    }

    return hr;
}

typedef struct _task_args {
    wchar_t server[260];
    BOOL has_server;
} task_args;

static const char* get_task_state(TASK_STATE state) {
    switch (state) {
        case TASK_STATE_DISABLED: return "DISABLED";
        case TASK_STATE_QUEUED: return "QUEUED";
        case TASK_STATE_READY: return "READY";
        case TASK_STATE_RUNNING: return "RUNNING";
        default: return "UNKNOWN";
    }
}


static void enumerate_folder_tasks(ITaskFolder *pFolder, int depth, int *totalCount) {
    HRESULT hr;
    BSTR folderPath = NULL;
    IRegisteredTaskCollection *pTaskCollection = NULL;
    ITaskFolderCollection *pSubfolders = NULL;
    LONG taskCount = 0;
    LONG folderCount = 0;
    VARIANT vIndex;
    char pathBuffer[512];
    char nameBuffer[256];
    char dateBuffer[64];
    
    
    if (depth > 10) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Max folder depth reached\n");
        return;
    }
    
    
    hr = pFolder->lpVtbl->get_Path(pFolder, &folderPath);
    if (FAILED(hr) || folderPath == NULL) {
        return;
    }
    
    inline_memset(pathBuffer, 0, sizeof(pathBuffer));
    wide_to_utf8(folderPath, pathBuffer, sizeof(pathBuffer));
    
    hr = pFolder->lpVtbl->GetTasks(pFolder, TASK_ENUM_HIDDEN, &pTaskCollection);
    if (SUCCEEDED(hr) && pTaskCollection != NULL) {
        hr = pTaskCollection->lpVtbl->get_Count(pTaskCollection, &taskCount);
        if (SUCCEEDED(hr) && taskCount > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[i] Folder: %s\n", pathBuffer);
            
            OLEAUT32$VariantInit(&vIndex);
            vIndex.vt = VT_I4;
            
            for (LONG i = 1; i <= taskCount && i <= 100; i++) {
                IRegisteredTask *pTask = NULL;
                BSTR taskName = NULL;
                BSTR taskPath = NULL;
                VARIANT_BOOL isEnabled = 0;
                TASK_STATE taskState = TASK_STATE_UNKNOWN;
                VARIANT vDate;
                BSTR dateStr = NULL;
                
                vIndex.lVal = i;
                hr = pTaskCollection->lpVtbl->get_Item(pTaskCollection, vIndex, &pTask);
                if (FAILED(hr) || pTask == NULL) continue;
                
                
                hr = pTask->lpVtbl->get_Name(pTask, &taskName);
                if (SUCCEEDED(hr) && taskName != NULL) {
                    inline_memset(nameBuffer, 0, sizeof(nameBuffer));
                    wide_to_utf8(taskName, nameBuffer, sizeof(nameBuffer));
                    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Task: %s\n", nameBuffer);
                    OLEAUT32$SysFreeString(taskName);
                }
                
                
                hr = pTask->lpVtbl->get_Path(pTask, &taskPath);
                if (SUCCEEDED(hr) && taskPath != NULL) {
                    inline_memset(pathBuffer, 0, sizeof(pathBuffer));
                    wide_to_utf8(taskPath, pathBuffer, sizeof(pathBuffer));
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] Path: %s\n", pathBuffer);
                    OLEAUT32$SysFreeString(taskPath);
                }
                
                
                hr = pTask->lpVtbl->get_Enabled(pTask, &isEnabled);
                if (SUCCEEDED(hr)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[i] Enabled: %s\n", isEnabled ? "Yes" : "No");
                }
                
                
                hr = pTask->lpVtbl->get_State(pTask, &taskState);
                if (SUCCEEDED(hr)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[i] State: %s\n", get_task_state(taskState));
                }
                
                
                OLEAUT32$VariantInit(&vDate);
                vDate.vt = VT_DATE;
                hr = pTask->lpVtbl->get_LastRunTime(pTask, &vDate.date);
                if (SUCCEEDED(hr) && vDate.date != 0) {
                    hr = OLEAUT32$VarFormatDateTime(&vDate, 0, 0, &dateStr);
                    if (SUCCEEDED(hr) && dateStr != NULL) {
                        inline_memset(dateBuffer, 0, sizeof(dateBuffer));
                        wide_to_utf8(dateStr, dateBuffer, sizeof(dateBuffer));
                        BeaconPrintf(CALLBACK_OUTPUT, "[i] Last Run: %s\n", dateBuffer);
                        OLEAUT32$SysFreeString(dateStr);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[i] Last Run: <format error>\n");
                    }
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[i] Last Run: Never\n");
                }
                
                
                OLEAUT32$VariantInit(&vDate);
                vDate.vt = VT_DATE;
                hr = pTask->lpVtbl->get_NextRunTime(pTask, &vDate.date);
                if (SUCCEEDED(hr) && vDate.date != 0) {
                    hr = OLEAUT32$VarFormatDateTime(&vDate, 0, 0, &dateStr);
                    if (SUCCEEDED(hr) && dateStr != NULL) {
                        inline_memset(dateBuffer, 0, sizeof(dateBuffer));
                        wide_to_utf8(dateStr, dateBuffer, sizeof(dateBuffer));
                        BeaconPrintf(CALLBACK_OUTPUT, "[i] Next Run: %s\n", dateBuffer);
                        OLEAUT32$SysFreeString(dateStr);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[i] Next Run: <format error>\n");
                    }
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[i] Next Run: Not scheduled\n");
                }
                
                OLEAUT32$VariantClear(&vDate);
                pTask->lpVtbl->Release(pTask);
                (*totalCount)++;
                
               
                if (*totalCount >= 200) {
                    BeaconPrintf(CALLBACK_OUTPUT, "\n[!] Task limit reached (200), stopping\n");
                    pTaskCollection->lpVtbl->Release(pTaskCollection);
                    OLEAUT32$SysFreeString(folderPath);
                    return;
                }
            }
            
            OLEAUT32$VariantClear(&vIndex);
        }
        pTaskCollection->lpVtbl->Release(pTaskCollection);
    }
    
    
    hr = pFolder->lpVtbl->GetFolders(pFolder, 0, &pSubfolders);
    if (SUCCEEDED(hr) && pSubfolders != NULL) {
        hr = pSubfolders->lpVtbl->get_Count(pSubfolders, &folderCount);
        if (SUCCEEDED(hr) && folderCount > 0) {
            OLEAUT32$VariantInit(&vIndex);
            vIndex.vt = VT_I4;
            
            for (LONG i = 1; i <= folderCount && i <= 50; i++) {
                ITaskFolder *pSubfolder = NULL;
                vIndex.lVal = i;
                hr = pSubfolders->lpVtbl->get_Item(pSubfolders, vIndex, &pSubfolder);
                if (SUCCEEDED(hr) && pSubfolder != NULL) {
                    enumerate_folder_tasks(pSubfolder, depth + 1, totalCount);
                    pSubfolder->lpVtbl->Release(pSubfolder);
                }
                
                if (*totalCount >= 200) break;
            }
            
            OLEAUT32$VariantClear(&vIndex);
        }
        pSubfolders->lpVtbl->Release(pSubfolders);
    }
    
    OLEAUT32$SysFreeString(folderPath);
}

static void perform_task_enumeration(task_args *args) {
    HRESULT hr;
    ITaskService *pService = NULL;
    ITaskFolder *pRootFolder = NULL;
    BSTR rootPath = NULL;
    VARIANT vServer, vNull;
    int totalCount = 0;
    const wchar_t *server = NULL;
    
    
    if (args != NULL && args->has_server && args->server[0] != L'\0') {
        server = args->server;
    } else {
        server = L"";
    }
    
    
    if (server != NULL && server[0] != L'\0') {
        char serverName[260];
        inline_memset(serverName, 0, sizeof(serverName));
        wide_to_utf8(server, serverName, sizeof(serverName));
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerating scheduled tasks on remote server: %s\n", serverName);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerating scheduled tasks on local system...\n");
    }
    

    hr = OLE32$CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        if (hr == E_NOINTERFACE) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create Task Scheduler instance (E_NOINTERFACE: 0x%lx).\n", (unsigned long)hr);
            BeaconPrintf(CALLBACK_ERROR, "[-] This may indicate:\n");
            BeaconPrintf(CALLBACK_ERROR, "[-]   - Task Scheduler service is not running (check 'services.msc')\n");
            BeaconPrintf(CALLBACK_ERROR, "[-]   - COM registration issue with Task Scheduler\n");
            BeaconPrintf(CALLBACK_ERROR, "[-]   - Threading model mismatch (ensure STA mode; Beacon defaults to MTA)\n");
            BeaconPrintf(CALLBACK_ERROR, "[-]   - COM security initialization issue\n");
        } else if (hr == E_CLASS_NOT_REGISTERED) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create Task Scheduler instance (E_CLASS_NOT_REGISTERED: 0x%lx).\n", (unsigned long)hr);
            BeaconPrintf(CALLBACK_ERROR, "[-] Task Scheduler COM class is not registered on this system.\n");
            BeaconPrintf(CALLBACK_ERROR, "[-] Try: regsvr32 schedsvc.dll (as Administrator)\n");
        } else if (hr == CO_E_SERVER_EXEC_FAILURE) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create Task Scheduler instance (CO_E_SERVER_EXEC_FAILURE: 0x%lx).\n", (unsigned long)hr);
            BeaconPrintf(CALLBACK_ERROR, "[-] Task Scheduler service may have failed to start. Check service status.\n");
        } else if (hr == CO_E_NOTINITIALIZED) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create Task Scheduler instance (CO_E_NOTINITIALIZED: 0x%lx).\n", (unsigned long)hr);
            BeaconPrintf(CALLBACK_ERROR, "[-] COM was not properly initialized. This is an internal error.\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create Task Scheduler instance (0x%lx).\n", (unsigned long)hr);
            BeaconPrintf(CALLBACK_ERROR, "[-] Task Scheduler service may not be running or accessible.\n");
        }
        return;
    }
    
    
    if (pService == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance returned NULL interface pointer\n");
        return;
    }
    
    // Connect to Task Scheduler
    OLEAUT32$VariantInit(&vServer);
    OLEAUT32$VariantInit(&vNull);
    
    if (server != NULL && server[0] != L'\0') {
        vServer.vt = VT_BSTR;
        vServer.bstrVal = OLEAUT32$SysAllocString(server);
        if (vServer.bstrVal == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate BSTR for server name\n");
            goto cleanup;
        }
    }
    
    hr = pService->lpVtbl->Connect(pService, vServer, vNull, vNull, vNull);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to connect to Task Scheduler (0x%lx)\n", (unsigned long)hr);
        if (hr == CO_E_NOTINITIALIZED) {
            BeaconPrintf(CALLBACK_ERROR, "[-] COM was not properly initialized before Connect() call\n");
        }
        goto cleanup;
    }
    
    
    rootPath = OLEAUT32$SysAllocString(L"\\");
    if (rootPath == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate BSTR for root path\n");
        goto cleanup;
    }
    
    hr = pService->lpVtbl->GetFolder(pService, rootPath, &pRootFolder);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get root folder (0x%lx)\n", (unsigned long)hr);
        goto cleanup;
    }
    
    
    if (pRootFolder == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetFolder returned NULL interface pointer\n");
        goto cleanup;
    }
    
    
    enumerate_folder_tasks(pRootFolder, 0, &totalCount);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[i] Total tasks enumerated: %d\n", totalCount);
    
cleanup:
    if (pRootFolder != NULL) {
        pRootFolder->lpVtbl->Release(pRootFolder);
    }
    if (rootPath != NULL) {
        OLEAUT32$SysFreeString(rootPath);
    }
    if (vServer.vt == VT_BSTR && vServer.bstrVal != NULL) {
        OLEAUT32$VariantClear(&vServer);
    }
    OLEAUT32$VariantClear(&vNull);
    if (pService != NULL) {
        pService->lpVtbl->Release(pService);
    }
}

DWORD WINAPI StaThread(LPVOID lpParameter) {
    task_args *args = (task_args *)lpParameter;

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx failed in STA thread (0x%lx)\n", (unsigned long)hr);
        return 1;
    }


    hr = initialize_com_security();
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeSecurity failed (0x%lx)\n", (unsigned long)hr);
        OLE32$CoUninitialize();
        return 1;
    }

    // Run the COM operations
    perform_task_enumeration(args);

    OLE32$CoUninitialize();
    return 0;
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    task_args task_params;

    inline_memset(&task_params, 0, sizeof(task_params));

    // Parse optional server argument
    if (alen > 0) {
        BeaconDataParse(&parser, args, (int)alen);
        char *serverArg = BeaconDataExtract(&parser, NULL);
        if (serverArg && serverArg[0] != '\0') {
            if (utf8_to_wide(serverArg, task_params.server, 260) > 0) {
                task_params.has_server = TRUE;
            }
        }
    }

    if (!task_params.has_server || task_params.server[0] == L'\0') {
        task_params.has_server = FALSE;
        task_params.server[0] = L'\0';
    }


    task_args *thread_args = (task_args *)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(task_args));

    if (!thread_args) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed for STA thread args (GLE: %ld)", KERNEL32$GetLastError());
        return;
    }

    *thread_args = task_params;

    HANDLE hThread = KERNEL32$CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)StaThread,
        (LPVOID)thread_args,
        0, NULL);

    if (hThread) {
        DWORD wait = KERNEL32$WaitForSingleObject(hThread, 30000);
        if (wait == WAIT_TIMEOUT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] STA thread timed out (30s) – deep recursion likely");
        } else if (wait != WAIT_OBJECT_0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] WaitForSingleObject failed (0x%lx)", wait);
        }
        KERNEL32$CloseHandle(hThread);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateThread failed (GLE: %ld)", KERNEL32$GetLastError());
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, thread_args);
}
