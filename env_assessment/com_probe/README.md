# com_probe BOF

Probe whether a COM object can be instantiated from a given CLSID. Tries in-process activation first (`CLSCTX_INPROC_SERVER`), falls back to local server (`CLSCTX_LOCAL_SERVER`). Objects are released after.

## Usage

```
com_probe <CLSID> [IID]
```

- `CLSID` — GUID string, e.g. `{AEB5B82E-51E7-41EA-9A0B-3D2C8BEDE7B4}`
- `IID` — optional interface ID (defaults to `IID_IUnknown`)

## Example Output

```
[i] Probing CLSID: {AEB5B82E-51E7-41EA-9A0B-3D2C8BEDE7B4} with IID: IID_IUnknown (default)
[i] Attempting CLSCTX_INPROC_SERVER activation...
[+] In-proc activation succeeded (HRESULT: S_OK (0x00000000))
[i] Object released cleanly after in-proc activation
```

```
[i] Probing CLSID: {00000000-0000-0000-0000-000000000000} with IID: IID_IUnknown (default)
[-] In-proc activation failed (HRESULT: CLASS_E_CLASSNOTAVAILABLE (0x80040154))
[-] Local server activation failed (HRESULT: CLASS_E_CLASSNOTAVAILABLE (0x80040154))
```
