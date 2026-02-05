#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "beacon.h"

#ifndef WINAPI
#define WINAPI __attribute__((__stdcall__))
#endif

#ifndef STDMETHODCALLTYPE
#define STDMETHODCALLTYPE __stdcall
#endif
#ifndef CONST_VTBL
#define CONST_VTBL
#endif

#ifndef CLSCTX_INPROC_SERVER
#define CLSCTX_INPROC_SERVER 0x1
#endif

#ifndef CLSCTX_LOCAL_SERVER
#define CLSCTX_LOCAL_SERVER 0x4
#endif

#ifndef COINIT_APARTMENTTHREADED
#define COINIT_APARTMENTTHREADED 0x2
#endif

#ifndef SUCCEEDED
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#endif

#ifndef FAILED
#define FAILED(hr) (((HRESULT)(hr)) < 0)
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

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize();
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT void WINAPI OLE32$CoTaskMemFree(LPVOID pv);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR lpString);

const GUID CLSID_DesktopWallpaper = {0xc2cf3110, 0x460e, 0x4fc1, {0xb9, 0xd0, 0x8a, 0x1c, 0x0c, 0x9c, 0xc4, 0xbd}};
const GUID IID_IDesktopWallpaper = {0xb92b56a9, 0x8b55, 0x4e14, {0x9a, 0x89, 0x01, 0x99, 0xbb, 0xb6, 0xf9, 0x3b}};

typedef enum DESKTOP_WALLPAPER_POSITION {
  DWPOS_CENTER = 0
} DESKTOP_WALLPAPER_POSITION;

typedef enum DESKTOP_SLIDESHOW_DIRECTION { DSD_FORWARD = 0 } DESKTOP_SLIDESHOW_DIRECTION;
typedef enum DESKTOP_SLIDESHOW_OPTIONS { DSO_NONE = 0 } DESKTOP_SLIDESHOW_OPTIONS;
typedef enum DESKTOP_SLIDESHOW_STATE { DSS_NONE = 0 } DESKTOP_SLIDESHOW_STATE;

typedef struct IShellItemArray IShellItemArray;

typedef struct IDesktopWallpaperVtbl {
  HRESULT(WINAPI *QueryInterface)(void *this, REFIID riid, void **ppvObject);
  ULONG(WINAPI *AddRef)(void *this);
  ULONG(WINAPI *Release)(void *this);
  HRESULT(WINAPI *SetWallpaper)(void *this, LPCWSTR monitorID, LPCWSTR wallpaper);
  HRESULT(WINAPI *GetWallpaper)(void *this, LPCWSTR monitorID, LPWSTR *wallpaper);
  HRESULT(WINAPI *GetMonitorDevicePathAt)(void *this, UINT monitorIndex, LPWSTR *monitorID);
  HRESULT(WINAPI *GetMonitorCount)(void *this, UINT *count);
  HRESULT(WINAPI *GetMonitorRECT)(void *this, LPCWSTR monitorID, RECT *displayRect);
  HRESULT(WINAPI *SetBackgroundColor)(void *this, COLORREF color);
  HRESULT(WINAPI *GetBackgroundColor)(void *this, COLORREF *color);
  HRESULT(WINAPI *SetPosition)(void *this, DESKTOP_WALLPAPER_POSITION position);
  HRESULT(WINAPI *GetPosition)(void *this, DESKTOP_WALLPAPER_POSITION *position);
  HRESULT(WINAPI *SetSlideshow)(void *this, IShellItemArray *items);
  HRESULT(WINAPI *GetSlideshow)(void *this, IShellItemArray **items);
  HRESULT(WINAPI *SetSlideshowOptions)(void *this, DESKTOP_SLIDESHOW_OPTIONS options, UINT slideshowTick);
  HRESULT(WINAPI *GetSlideshowOptions)(void *this, DESKTOP_SLIDESHOW_OPTIONS *options, UINT *slideshowTick);
  HRESULT(WINAPI *AdvanceSlideshow)(void *this, LPCWSTR monitorID, DESKTOP_SLIDESHOW_DIRECTION direction);
  HRESULT(WINAPI *GetStatus)(void *this, DESKTOP_SLIDESHOW_STATE *state);
  HRESULT(WINAPI *Enable)(void *this, BOOL enable);
} IDesktopWallpaperVtbl;

typedef struct IDesktopWallpaper {
  const IDesktopWallpaperVtbl *lpVtbl;
} IDesktopWallpaper;

static void print_wallpaper(LPCWSTR monitorId, LPCWSTR wallpaperPath, UINT index) {
  int monitorLen = KERNEL32$lstrlenW(monitorId);
  if (wallpaperPath != NULL) {
    int wallpaperLen = KERNEL32$lstrlenW(wallpaperPath);
    if (wallpaperLen > 0) {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] Monitor %u (%.*ls): %.*ls\n", index, monitorLen, monitorId, wallpaperLen, wallpaperPath);
    } else {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] Monitor %u (%.*ls): No central wallpaper configured (not from network share)\n", index, monitorLen, monitorId);
    }
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Monitor %u (%.*ls): No central wallpaper configured (not from network share)\n", index, monitorLen, monitorId);
  }
}

void go(char *args, unsigned long alen) {
  (void)args;
  (void)alen;

  BeaconPrintf(CALLBACK_OUTPUT, "[i] Initializing COM...\n");

  BOOL comInitialized = FALSE;
  HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  if (hr == S_OK || hr == S_FALSE) {
    comInitialized = TRUE;
  } else if (hr == (HRESULT)0x80010106) {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] COM already initialized (different mode), continuing...\n");
  } else if (FAILED(hr)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] CoInitializeEx failed: 0x%08lx\n", hr);
    return;
  }

  IDesktopWallpaper *desktopWallpaper = NULL;
  hr = OLE32$CoCreateInstance(&CLSID_DesktopWallpaper, NULL, CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, &IID_IDesktopWallpaper, (void **)&desktopWallpaper);
  if (FAILED(hr) || desktopWallpaper == NULL) {
    BeaconPrintf(CALLBACK_ERROR, "[!] CoCreateInstance failed: 0x%08lx\n", hr);
    if (comInitialized) OLE32$CoUninitialize();
    return;
  }

  UINT monitorCount = 0;
  hr = desktopWallpaper->lpVtbl->GetMonitorCount(desktopWallpaper, &monitorCount);
  if (FAILED(hr)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] GetMonitorCount failed: 0x%08lx\n", hr);
    desktopWallpaper->lpVtbl->Release(desktopWallpaper);
    if (comInitialized) OLE32$CoUninitialize();
    return;
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[i] Found %u monitor(s)\n", monitorCount);

  for (UINT i = 0; i < monitorCount; ++i) {
    LPWSTR monitorId = NULL;
    hr = desktopWallpaper->lpVtbl->GetMonitorDevicePathAt(desktopWallpaper, i, &monitorId);
    if (FAILED(hr) || monitorId == NULL) {
      BeaconPrintf(CALLBACK_ERROR, "[!] GetMonitorDevicePathAt(%u) failed: 0x%08lx\n", i, hr);
      if (monitorId != NULL) {
        OLE32$CoTaskMemFree(monitorId);
      }
      continue;
    }

    LPWSTR wallpaperPath = NULL;
    hr = desktopWallpaper->lpVtbl->GetWallpaper(desktopWallpaper, monitorId, &wallpaperPath);
    if (FAILED(hr)) {
      BeaconPrintf(CALLBACK_ERROR, "[!] GetWallpaper(%u) failed: 0x%08lx\n", i, hr);
      OLE32$CoTaskMemFree(monitorId);
      if (wallpaperPath != NULL) {
        OLE32$CoTaskMemFree(wallpaperPath);
      }
      continue;
    }

    print_wallpaper(monitorId, wallpaperPath, i);

    if (wallpaperPath != NULL) {
      OLE32$CoTaskMemFree(wallpaperPath);
    }
    OLE32$CoTaskMemFree(monitorId);
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumeration complete\n");

  desktopWallpaper->lpVtbl->Release(desktopWallpaper);
  if (comInitialized) OLE32$CoUninitialize();
}
