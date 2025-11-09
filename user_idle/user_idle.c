#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif
#ifndef WINAPI
#define WINAPI __stdcall
#endif


typedef void*        PVOID;
typedef void*        HMODULE;
typedef void*        HANDLE;
typedef unsigned short wchar_t;
typedef const wchar_t* LPCWSTR;
typedef const char*  LPCSTR;
typedef void*        FARPROC;
typedef unsigned long DWORD;
typedef unsigned int  UINT;
typedef int           BOOL;

#define TRUE  1
#define FALSE 0


DECLSPEC_IMPORT void BeaconPrintf(int type, char *fmt, ...);
#ifndef CALLBACK_OUTPUT
#define CALLBACK_OUTPUT 0x0
#endif
#ifndef CALLBACK_ERROR
#define CALLBACK_ERROR  0x0d
#endif


DECLSPEC_IMPORT BOOL   WINAPI USER32$GetLastInputInfo(PVOID);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI USER32$GetGuiResources(HANDLE, DWORD);


typedef struct _LASTINPUTINFO_MIN {
    UINT  cbSize;
    DWORD dwTime;
} LASTINPUTINFO_MIN, *PLASTINPUTINFO_MIN;

#define GR_GDIOBJECTS  0u  // user32!GetGuiResources flag for GDI handles
#define GR_USEROBJECTS 1u  // user32!GetGuiResources flag for USER handles


static inline DWORD delta_ms(DWORD now, DWORD then) {
    return (DWORD)(now - then); 
}


void go(char *args, unsigned long alen) {
    (void)args; (void)alen;


    LASTINPUTINFO_MIN li;
    li.cbSize = (UINT)sizeof(LASTINPUTINFO_MIN);
    li.dwTime = 0;

    DWORD idle_sec = 0xFFFFFFFF;
    if (USER32$GetLastInputInfo((PVOID)&li)) {
        DWORD now = KERNEL32$GetTickCount();
        DWORD ms  = delta_ms(now, li.dwTime);
        idle_sec  = ms / 1000u;
    }

    HANDLE self = KERNEL32$GetCurrentProcess();
    DWORD gdi   = USER32$GetGuiResources(self, GR_GDIOBJECTS);
    DWORD user  = USER32$GetGuiResources(self, GR_USEROBJECTS);

    const char* cat = "Idle";
    if (idle_sec != 0xFFFFFFFF) {
        if (idle_sec < 60u)       cat = "Active";
        else if (idle_sec < 300u) cat = "Warm";
    }

    if (idle_sec == 0xFFFFFFFF) {
        BeaconPrintf(CALLBACK_OUTPUT, "IDLE_SEC=Unknown CAT=Unknown GDI_HANDLES=%lu USER_HANDLES=%lu",
                     (unsigned long)gdi, (unsigned long)user);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "IDLE_SEC=%lu CAT=%s GDI_HANDLES=%lu USER_HANDLES=%lu",
                     (unsigned long)idle_sec, (char*)cat, (unsigned long)gdi, (unsigned long)user);
    }
}
