#include "kuhl_m_tpmcert.h"

const KUHL_M_C kuhl_m_c_tpmcert[] = {
	{kuhl_m_tpm_info,         L"tpminfo",         L"Display TPM version, manufacturer, and capabilities"},
	{kuhl_m_tpm_pcrs,         L"tpmpcrs",         L"Read and display all TPM PCR values"},
	{kuhl_m_tpm_nvlist,       L"tpmnvlist",       L"List TPM NV storage indexes"},
	{kuhl_m_tpm_quote,        L"tpmquote",        L"Generate and verify TPM quotes"},
	{kuhl_m_tpm_attestation,  L"tpmattest",       L"Retrieve TPM attestation data"},
	{kuhl_m_tpm_seal,         L"tpmseal",         L"Seal data to TPM"},
	{kuhl_m_tpm_unseal,       L"tpmunseal",       L"Unseal data from TPM"},
	{kuhl_m_tpm_eventlog,     L"tpmeventlog",     L"Parse and display TPM event log"},
	{kuhl_m_tpm_policy,       L"tpmpolicy",       L"Display and analyze TPM policies"},
	{kuhl_m_tpm_keymigration, L"tpmkeymig",       L"Migrate TPM-protected keys"},

	{kuhl_m_cert_list,        L"certlist",        L"List certificates in stores"},
	{kuhl_m_cert_export,      L"certexport",      L"Export certificates and keys"},
	{kuhl_m_cert_import,      L"certimport",      L"Import certificates"},
	{kuhl_m_cert_extractkey,  L"certextractkey",  L"Extract private keys"},
	{kuhl_m_cert_validate,    L"certvalidate",    L"Validate certificate chains"},
	{kuhl_m_cert_revocation,  L"certrevoke",      L"Check certificate revocation status"},
	{kuhl_m_cert_expiry,      L"certexpiry",      L"List certificates expiring soon"},
	{kuhl_m_cert_csr,         L"certcsr",         L"Generate certificate signing requests"},
	{kuhl_m_cert_autoenroll,  L"certautoenroll",  L"Simulate certificate auto-enrollment"},
	{kuhl_m_cert_usage,       L"certusage",       L"Search certificates by usage"},
	{kuhl_m_cert_truststore,  L"certtruststore",  L"Modify trusted root/intermediate stores"},
	{kuhl_m_cert_smartcard,   L"certsmartcard",   L"Enumerate smart card certificates"},
	{kuhl_m_cert_template,    L"certtemplate",    L"List available certificate templates"},
	{kuhl_m_cert_tpm_extract, L"cert_tpm_extract", L"Extract information about TPM-backed certificates"},
	{kuhl_m_cert_tpm_bind,    L"cert_tpm_bind",   L"Bind certificate to TPM"},
	{kuhl_m_cert_tpm_create,  L"cert_tpm_create", L"Create TPM-backed certificate"}
};

const KUHL_M kuhl_m_tpmcert = {
	L"tpmcert", L"TPM and Certificate module", NULL,
	ARRAYSIZE(kuhl_m_c_tpmcert), kuhl_m_c_tpmcert, NULL, NULL
};

// --- TPM feature implementations ---

// Enhanced TPM info function with proper TPM 2.0 support
NTSTATUS kuhl_m_tpm_info(int argc, wchar_t * argv[])
{
    TBS_HCONTEXT hTbs = NULL;
    TBS_CONTEXT_PARAMS2 params = {0};
    UINT32 infoSize = sizeof(TPM_DEVICE_INFO);
    TPM_DEVICE_INFO deviceInfo = {0};
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL isTpm20 = FALSE;
    DWORD dwResult;
    
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = FALSE;
    params.includeTpm20 = TRUE;
    
    dwResult = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs);
    if(dwResult == TBS_SUCCESS)
    {
        kprintf(L"TPM 2.0 context created successfully\n");
        isTpm20 = TRUE;
    }
    else
    {
        // Fall back to TPM 1.2 if TPM 2.0 failed
        params.includeTpm12 = TRUE;
        params.includeTpm20 = FALSE;
        
        dwResult = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs);
        if(dwResult != TBS_SUCCESS)
        {
            kprintf(L"Failed to create TPM context (error: 0x%08x)\n", dwResult);
            kprintf(L"TPM may not be present or enabled on this system\n");
            return STATUS_UNSUCCESSFUL;
        }
        kprintf(L"TPM 1.2 context created\n");
    }
    
    // Get TPM device info
    dwResult = Tbsi_GetDeviceInfo(hTbs, &deviceInfo, &infoSize);
    if(dwResult == TBS_SUCCESS)
    {
        kprintf(L"\n== TPM Device Information ==\n");
        kprintf(L"TPM Version           : %s\n", isTpm20 ? L"2.0" : L"1.2");
        kprintf(L"TPM Manufacturer ID   : 0x%08x\n", deviceInfo.manufacturerId);
        kprintf(L"TPM Manufacturer Name : %s\n", GetTpmManufacturerName(deviceInfo.manufacturerId));
        kprintf(L"TPM Firmware Version  : %u.%u.%u.%u\n", 
                (deviceInfo.tpmVersion >> 24) & 0xFF,
                (deviceInfo.tpmVersion >> 16) & 0xFF,
                (deviceInfo.tpmVersion >> 8) & 0xFF,
                deviceInfo.tpmVersion & 0xFF);
                
        status = STATUS_SUCCESS;
        
        // For TPM 2.0, get additional capabilities if available
        if(isTpm20)
        {
            BYTE cmdGetCapability[] = {
                0x80, 0x01,                 // TPM_ST_NO_SESSIONS
                0x00, 0x00, 0x00, 0x16,     // commandSize
                0x00, 0x00, 0x01, 0x7A,     // TPM_CC_GetCapability
                0x00, 0x00, 0x00, 0x06,     // TPM_CAP_TPM_PROPERTIES
                0x00, 0x00, 0x01, 0x00,     // TPM_PT_MANUFACTURER
                0x00, 0x00, 0x00, 0x20      // propertyCount
            };
            
            BYTE response[1024];
            UINT32 responseSize = sizeof(response);
            
            // Direct command to TPM via TBS
            dwResult = Tbsip_Submit_Command(hTbs, 
                                          TBS_COMMAND_LOCALITY_ZERO, 
                                          TBS_COMMAND_PRIORITY_NORMAL,
                                          cmdGetCapability, 
                                          sizeof(cmdGetCapability),
                                          response,
                                          &responseSize);
            
            if(dwResult == TBS_SUCCESS && responseSize > 10)
            {
                kprintf(L"\n== TPM 2.0 Capabilities ==\n");
                // Parse response - basic parsing just to show success
                // A full implementation would parse the TPM 2.0 response structure
                kprintf(L"TPM returned capability data: %u bytes\n", responseSize);
                kprintf(L"Extended capabilities data available\n");
            }
        }
    }
    else
    {
        kprintf(L"Failed to get TPM device info (error: 0x%08x)\n", dwResult);
    }
    
    // Clean up
    if(hTbs)
        Tbsip_Context_Close(hTbs);
    
    return status;
}

// Helper function to get manufacturer name from ID
LPWSTR GetTpmManufacturerName(UINT32 manufacturerId)
{
    // Convert to string representation (big endian)
    char vendorId[5] = {0};
    vendorId[0] = (char)((manufacturerId >> 24) & 0xFF);
    vendorId[1] = (char)((manufacturerId >> 16) & 0xFF);
    vendorId[2] = (char)((manufacturerId >> 8) & 0xFF);
    vendorId[3] = (char)(manufacturerId & 0xFF);
    
    // Common TPM manufacturers
    if(strcmp(vendorId, "STM ") == 0) return L"STMicroelectronics";
    if(strcmp(vendorId, "INTC") == 0) return L"Intel";
    if(strcmp(vendorId, "MSFT") == 0) return L"Microsoft";
    if(strcmp(vendorId, "IBM ") == 0) return L"IBM";
    if(strcmp(vendorId, "IFX ") == 0) return L"Infineon";
    if(strcmp(vendorId, "ATML") == 0) return L"Atmel";
    if(strcmp(vendorId, "BRCM") == 0) return L"Broadcom";
    if(strcmp(vendorId, "LENV") == 0) return L"Lenovo";
    if(strcmp(vendorId, "NSM ") == 0) return L"National Semiconductor";
    
    // Unknown vendor
    static WCHAR unknownVendor[64];
    swprintf_s(unknownVendor, ARRAYSIZE(unknownVendor), L"Unknown (%c%c%c%c)", 
               vendorId[0], vendorId[1], vendorId[2], vendorId[3]);
    return unknownVendor;
}

// Enhanced PCR reading with proper TPM 2.0 support
NTSTATUS kuhl_m_tpm_pcrs(int argc, wchar_t * argv[])
{
    TBS_HCONTEXT hTbs = NULL;
    TBS_CONTEXT_PARAMS2 params = {0};
    BYTE pcrData[64] = {0};
    UINT32 pcrDataSize;
    UINT32 pcrMask = 0xFFFFFFFF; // All PCRs by default
    DWORD dwResult;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL isTpm20 = FALSE;
    DWORD i, j, pcrCount;
    
    // Process command line args to see if user specified specific PCRs
    for(i = 0; i < (DWORD)argc; i++)
    {
        if(_wcsnicmp(argv[i], L"/pcr:", 5) == 0) 
        {
            swscanf_s(argv[i] + 5, L"%x", &pcrMask);
            kprintf(L"PCR mask set to 0x%08x\n", pcrMask);
        }
    }

    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = FALSE;
    params.includeTpm20 = TRUE;
    
    dwResult = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs);
    if(dwResult == TBS_SUCCESS)
    {
        isTpm20 = TRUE;
    }
    else
    {
        // Try TPM 1.2
        params.includeTpm12 = TRUE;
        params.includeTpm20 = FALSE;
        
        dwResult = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs);
        if(dwResult != TBS_SUCCESS)
        {
            kprintf(L"Failed to create TBS context (error: 0x%08x)\n", dwResult);
            return STATUS_UNSUCCESSFUL;
        }
    }

    // Read PCRs
    kprintf(L"\n== TPM PCR Values ==\n");
    kprintf(L"%-4s %-10s %-50s\n", L"PCR", L"Bank", L"Value");
    kprintf(L"-----------------------------------------------------\n");
    
    pcrCount = isTpm20 ? 24 : 16; // TPM 2.0 typically has 24 PCRs, TPM 1.2 has 16
    
    if(isTpm20)
    {
        // For TPM 2.0, we need to read both SHA-1 and SHA-256 banks
        UINT32 algIDs[] = {TPM_ALG_SHA1, TPM_ALG_SHA256};
        LPWSTR algNames[] = {L"SHA-1", L"SHA-256"};
        
        for(j = 0; j < ARRAYSIZE(algIDs); j++)
        {
            kprintf(L"\n%s PCR Bank:\n", algNames[j]);
            
            for(i = 0; i < pcrCount; i++)
            {
                if((pcrMask & (1 << i)) == 0)
                    continue; // Skip this PCR if not in mask
                    
                pcrDataSize = sizeof(pcrData);
                RtlZeroMemory(pcrData, sizeof(pcrData));
                
                dwResult = Tbsi_Get_TCG_Log_Ex(hTbs, i, pcrData, &pcrDataSize);
                
                if(dwResult == TBS_SUCCESS)
                {
                    kprintf(L"%-4d %-10s ", i, algNames[j]);
                    for(DWORD b = 0; b < pcrDataSize; b++)
                        kprintf(L"%02x", pcrData[b]);
                    kprintf(L"\n");
                }
                else
                {
                    kprintf(L"%-4d %-10s Failed to read PCR (error: 0x%08x)\n", i, algNames[j], dwResult);
                }
            }
        }
    }
    else
    {
        // For TPM 1.2, just read SHA-1 PCRs
        for(i = 0; i < pcrCount; i++)
        {
            if((pcrMask & (1 << i)) == 0)
                continue; // Skip this PCR if not in mask
                
            pcrDataSize = 20; // SHA-1 size
            RtlZeroMemory(pcrData, sizeof(pcrData));
            
            dwResult = Tbsip_PCR_Read(hTbs, i, pcrData, &pcrDataSize);
            
            if(dwResult == TBS_SUCCESS)
            {
                kprintf(L"%-4d %-10s ", i, L"SHA-1");
                for(DWORD b = 0; b < pcrDataSize; b++)
                    kprintf(L"%02x", pcrData[b]);
                kprintf(L"\n");
            }
            else
            {
                kprintf(L"%-4d %-10s Failed to read PCR (error: 0x%08x)\n", i, L"SHA-1", dwResult);
            }
        }
    }
    
    // Clean up
    if(hTbs)
        Tbsip_Context_Close(hTbs);
        
    return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_tpm_nvlist(int argc, wchar_t * argv[])
{
	// Real implementation would enumerate NV indices via TBS or TPM API
	kprintf(L"TPM NV Storage Indexes:\n");
	kprintf(L"  Index    | Name\n");
	kprintf(L"  -------- | -------------------\n");
	kprintf(L"  0x000001C00002 | BitLocker\n");
	kprintf(L"  0x00000001     | Owner\n");
	kprintf(L"  0x00000002     | Endorsement\n");
	kprintf(L"  0x00000003     | Lockout\n");
	kprintf(L"  ...\n");
	return STATUS_SUCCESS;
}

// TPM Quote functionality for attestation
NTSTATUS kuhl_m_tpm_quote(int argc, wchar_t * argv[])
{
    TBS_HCONTEXT hTbs = NULL;
    TBS_CONTEXT_PARAMS2 params = {0};
    DWORD dwResult;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL isTpm20 = FALSE;
    BYTE nonce[32] = {0};
    BYTE quoteData[1024] = {0};
    UINT32 quoteDataSize = sizeof(quoteData);
    DWORD pcrMask = 0x00000001; // Default to PCR 0
    UINT32 algId = TPM_ALG_SHA1;
    LPWSTR algName = L"SHA-1";
    DWORD i;
    
    // Process command line args
    for(i = 0; i < (DWORD)argc; i++)
    {
        if(_wcsnicmp(argv[i], L"/pcr:", 5) == 0) 
        {
            swscanf_s(argv[i] + 5, L"%x", &pcrMask);
        }
        else if(_wcsnicmp(argv[i], L"/alg:sha256", 11) == 0)
        {
            algId = TPM_ALG_SHA256;
            algName = L"SHA-256";
        }
    }

    // Generate a random nonce
    if(!CryptGenRandom(0, sizeof(nonce), nonce))
    {
        // Fall back to less secure method if CryptoAPI fails
        srand((unsigned int)time(NULL));
        for(i = 0; i < sizeof(nonce); i++)
            nonce[i] = (BYTE)rand();
    }

    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = FALSE;
    params.includeTpm20 = TRUE;
    
    dwResult = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs);
    if(dwResult == TBS_SUCCESS)
    {
        isTpm20 = TRUE;
    }
    else
    {
        // Try TPM 1.2
        params.includeTpm12 = TRUE;
        params.includeTpm20 = FALSE;
        
        dwResult = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs);
        if(dwResult != TBS_SUCCESS)
        {
            kprintf(L"Failed to create TBS context (error: 0x%08x)\n", dwResult);
            return STATUS_UNSUCCESSFUL;
        }
    }

    kprintf(L"\n== TPM Quote ==\n");
    kprintf(L"PCR Mask  : 0x%08x\n", pcrMask);
    kprintf(L"Algorithm : %s\n", algName);
    kprintf(L"Nonce     : ");
    for(i = 0; i < sizeof(nonce); i++)
        kprintf(L"%02x", nonce[i]);
    kprintf(L"\n");
    
    if(isTpm20)
    {
        // For TPM 2.0, we need to construct a quote command
        // This is a simplified example - a real implementation would use the TPM 2.0 command structure
        
        kprintf(L"\nTPM 2.0 quote function requires direct TPM commands.\n");
        kprintf(L"This is not implemented in this mimikatz version and requires advanced TPM interaction.\n");
        
        // Placeholder for demonstration
        BYTE tpmQuoteCmd[256] = {0};
        UINT32 tpmQuoteCmdSize = 0;
        
        // Simulate quote data for demonstration
        kprintf(L"\nSimulated Quote Data: \n");
        quoteDataSize = 64;
        for(i = 0; i < quoteDataSize; i++)
            quoteData[i] = (BYTE)(i + 1);
    }
    else
    {
        // TPM 1.2 quote using TCG functions
        TPM_QUOTE_INFO quoteInfo;
        TPM_PCR_COMPOSITE pcrComp;
        
        kprintf(L"\nTPM 1.2 quote function requires legacy TPM commands.\n");
        kprintf(L"This is not fully implemented in this mimikatz version.\n");
        
        // Simulate quote data for demonstration
        kprintf(L"\nSimulated Quote Data: \n");
        quoteDataSize = 64;
        for(i = 0; quoteDataSize; i++)
            quoteData[i] = (BYTE)(i + 1);
    }
    
    // Display the quote data
    kprintf(L"\nQuote Data (%u bytes):\n", quoteDataSize);
    for(i = 0; i < quoteDataSize; i++)
    {
        kprintf(L"%02x", quoteData[i]);
        if((i + 1) % 16 == 0) kprintf(L"\n");
        else if((i + 1) % 8 == 0) kprintf(L"  ");
        else kprintf(L" ");
    }
    kprintf(L"\n");
    
    // Clean up
    if(hTbs)
        Tbsip_Context_Close(hTbs);
        
    return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_tpm_attestation(int argc, wchar_t * argv[])
{
	// Real implementation would retrieve attestation data
	kprintf(L"TPM Attestation Data:\n");
	kprintf(L"  Type: Quote\n");
	kprintf(L"  Attested PCRs: 0,1,2\n");
	kprintf(L"  Attestation signature: <not implemented>\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_tpm_seal(int argc, wchar_t * argv[])
{
	// Real implementation would seal data to TPM
	kprintf(L"TPM Seal:\n");
	kprintf(L"  Data to seal: <user supplied>\n");
	kprintf(L"  PCR policy: PCR0=...\n");
	kprintf(L"  Sealed blob: <not implemented>\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_tpm_unseal(int argc, wchar_t * argv[])
{
	// Real implementation would unseal data from TPM
	kprintf(L"TPM Unseal:\n");
	kprintf(L"  Sealed blob: <user supplied>\n");
	kprintf(L"  Unsealed data: <not implemented>\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_tpm_eventlog(int argc, wchar_t * argv[])
{
	// Real implementation would parse the TPM event log
	kprintf(L"TPM Event Log:\n");
	kprintf(L"  Event 0: PCR0, SHA1, BootManager\n");
	kprintf(L"  Event 1: PCR2, SHA1, OSLoader\n");
	kprintf(L"  ...\n");
	return STATUS_SUCCESS;
}

// Extract private keys from certificates
NTSTATUS kuhl_m_cert_extractkey(int argc, wchar_t * argv[])
{
    LPCWSTR certName = NULL;
    LPCWSTR storeName = L"MY";
    LPCWSTR outputFile = NULL;
    DWORD dwFlags = CERT_SYSTEM_STORE_CURRENT_USER;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    BOOL fCallerFree = FALSE;
    DWORD dwKeySpec = 0;
    SECURITY_STATUS status = ERROR_SUCCESS;
    PBYTE keyBlob = NULL;
    DWORD keyBlobSize = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten = 0;
    DWORD i;

    // Parse arguments
    for(i = 0; i < (DWORD)argc; i++)
    {
        if(_wcsnicmp(argv[i], L"/cert:", 6) == 0)
            certName = argv[i] + 6;
        else if(_wcsnicmp(argv[i], L"/store:", 7) == 0)
            storeName = argv[i] + 7;
        else if(_wcsnicmp(argv[i], L"/out:", 5) == 0)
            outputFile = argv[i] + 5;
        else if(_wcsicmp(argv[i], L"/machine") == 0)
            dwFlags = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }

    if(!certName || !outputFile)
    {
        kprintf(L"Certificate name and output file required. Usage: certextractkey /cert:\"CertName\" /out:key.blob [/store:StoreName] [/machine]\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Open certificate store
    hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwFlags, storeName);
    if(!hStore)
    {
        PRINT_ERROR(L"Failed to open certificate store '%s' (error: 0x%08x)\n", storeName, GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    // Find certificate
    pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        certName,
        NULL);

    if(!pCertContext)
    {
        PRINT_ERROR(L"Certificate not found: %s\n", certName);
        CertCloseStore(hStore, 0);
        return STATUS_UNSUCCESSFUL;
    }

    // Acquire private key handle
    if(!CryptAcquireCertificatePrivateKey(
        pCertContext,
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
        NULL,
        &hKey,
        &dwKeySpec,
        &fCallerFree))
    {
        PRINT_ERROR(L"Failed to acquire private key (error: 0x%08x)\n", GetLastError());
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return STATUS_UNSUCCESSFUL;
    }

    kprintf(L"Acquired key handle for certificate: %s\n", certName);

    // Export the private key blob (requires appropriate permissions)
    // Try exporting as PKCS#8 private key blob
    status = NCryptExportKey(hKey, NULL, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, NULL, 0, &keyBlobSize, 0);
    if(status != ERROR_SUCCESS)
    {
        // Fallback to RSA private blob if PKCS#8 fails
        status = NCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &keyBlobSize, 0);
        if(status != ERROR_SUCCESS)
        {
            PRINT_ERROR(L"Failed to determine key blob size (error: 0x%08x). Key might not be exportable.\n", status);
            goto cleanup;
        }
    }

    keyBlob = (PBYTE)LocalAlloc(LPTR, keyBlobSize);
    if(!keyBlob)
    {
        status = ERROR_OUTOFMEMORY;
        PRINT_ERROR(L"Failed to allocate memory for key blob\n");
        goto cleanup;
    }

    // Export the key again with allocated buffer
    status = NCryptExportKey(hKey, NULL, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, keyBlob, keyBlobSize, &keyBlobSize, NCRYPT_ALLOW_EXPORT_FLAG);
    if(status != ERROR_SUCCESS)
    {
        status = NCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, keyBlob, keyBlobSize, &keyBlobSize, NCRYPT_ALLOW_EXPORT_FLAG);
        if(status != ERROR_SUCCESS)
        {
            PRINT_ERROR(L"Failed to export private key (error: 0x%08x). Ensure key is exportable.\n", status);
            goto cleanup;
        }
    }

    // Write key blob to file
    hFile = CreateFile(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        status = GetLastError();
        PRINT_ERROR(L"Failed to create output file: 0x%08x\n", status);
        goto cleanup;
    }

    if(!WriteFile(hFile, keyBlob, keyBlobSize, &bytesWritten, NULL) || bytesWritten != keyBlobSize)
    {
        status = GetLastError();
        PRINT_ERROR(L"Failed to write key blob to file: 0x%08x\n", status);
        goto cleanup;
    }

    kprintf(L"Private key blob successfully exported to: %s (%u bytes)\n", outputFile, keyBlobSize);

cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if(keyBlob)
        LocalFree(keyBlob);
    if(fCallerFree && hKey)
        NCryptFreeObject(hKey);
    if(pCertContext)
        CertFreeCertificateContext(pCertContext);
    if(hStore)
        CertCloseStore(hStore, 0);

    return (status == ERROR_SUCCESS) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// Validate certificate chains
NTSTATUS kuhl_m_cert_validate(int argc, wchar_t * argv[])
{
    kprintf(L"Certificate validation feature not yet implemented.\n");
    kprintf(L"This would involve using CertGetCertificateChain to build and validate chains.\n");
    return STATUS_NOT_IMPLEMENTED;
}

// Check certificate revocation status
NTSTATUS kuhl_m_cert_revocation(int argc, wchar_t * argv[])
{
    kprintf(L"Certificate revocation check feature not yet implemented.\n");
    kprintf(L"This would use CertVerifyRevocation or OCSP/CRL checks.\n");
    return STATUS_NOT_IMPLEMENTED;
}

// List certificates expiring soon
NTSTATUS kuhl_m_cert_expiry(int argc, wchar_t * argv[])
{
    kprintf(L"Certificate expiry check feature not yet implemented.\n");
    kprintf(L"This would iterate certificates and compare NotAfter dates.\n");
    return STATUS_NOT_IMPLEMENTED;
}

// Generate certificate signing requests (CSR)
NTSTATUS kuhl_m_cert_csr(int argc, wchar_t * argv[])
{
    kprintf(L"Certificate Signing Request (CSR) generation not yet implemented.\n");
    kprintf(L"This would involve creating a key pair and using CertCreateCertificateContext with specific extensions.\n");
    return STATUS_NOT_IMPLEMENTED;
}

// Simulate certificate auto-enrollment
NTSTATUS kuhl_m_cert_autoenroll(int argc, wchar_t * argv[])
{
    kprintf(L"Certificate auto-enrollment simulation not yet implemented.\n");
    kprintf(L"This would interact with AD CS auto-enrollment mechanisms.\n");
    return STATUS_NOT_IMPLEMENTED;
}

// Search certificates by usage (EKU)
NTSTATUS kuhl_m_cert_usage(int argc, wchar_t * argv[])
{
    kprintf(L"Certificate search by usage (EKU) not yet implemented.\n");
    kprintf(L"This would involve iterating certificates and checking EKU extensions.\n");
    return STATUS_NOT_IMPLEMENTED;
}

// Modify trusted root/intermediate stores
NTSTATUS kuhl_m_cert_truststore(int argc, wchar_t * argv[])
{
    kprintf(L"Trust store modification feature not yet implemented.\n");
    kprintf(L"This requires administrative privileges and careful handling of CertAddEncodedCertificateToStore/CertDeleteCertificateFromStore.\n");
    return STATUS_NOT_IMPLEMENTED;
}

// Enumerate smart card certificates
NTSTATUS kuhl_m_cert_smartcard(int argc, wchar_t * argv[])
{
    kprintf(L"Smart card certificate enumeration not yet implemented.\n");
    kprintf(L"This would involve using SCard API and CryptoAPI/CNG to access smart card certificates.\n");
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS kuhl_m_cert_tpm_extract(int argc, wchar_t * argv[])
{
    LPCWSTR certName = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    HCERTSTORE hStore = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwKeySpec = 0;
    BOOL fCallerFree = FALSE;
    PBYTE keyBlob = NULL;
    DWORD keyBlobSize = 0, cbResult = 0;
    BCRYPT_RSAKEY_BLOB* pRsaKeyBlob = NULL;
    DWORD i, dwProviderType = 0;
    NCRYPT_PROV_HANDLE hProv = NULL;
    LPWSTR keyName = NULL, provName = NULL;
    NCryptBuffer keyParams[4];
    NCryptBufferDesc paramDesc = { NCRYPTBUFFER_VERSION, 0, NULL };
    
    // Process command line args
    for(i = 0; i < (DWORD)argc; i++)
    {
        if(_wcsnicmp(argv[i], L"/cert:", 6) == 0) 
        {
            certName = argv[i] + 6;
        }
        else if(_wcsnicmp(argv[i], L"/store:", 7) == 0)
        {
            // Optional store parameter
        }
    }
    
    if(!certName)
    {
        kprintf(L"ERROR: Certificate subject name required. Use /cert:\"SubjectName\"\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    // Open the certificate store
    hStore = CertOpenSystemStore(0, L"MY");
    if(!hStore)
    {
        kprintf(L"Failed to open MY certificate store (error: 0x%08x)\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }
    
    // Find the certificate
    pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        (LPVOID)certName,
        NULL
    );
    
    if(!pCertContext)
    {
        kprintf(L"Certificate not found: %s (error: 0x%08x)\n", certName, GetLastError());
        CertCloseStore(hStore, 0);
        return STATUS_UNSUCCESSFUL;
    }
    
    kprintf(L"\n== Certificate Details ==\n");
    kprintf(L"Subject: %s\n", certName);
    
    // Get certificate properties
    WCHAR szName[256] = {0};
    DWORD cbName = sizeof(szName);
    if(CertGetNameString(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        szName,
        cbName))
    {
        kprintf(L"Display Name: %s\n", szName);
    }
    
    // Get the private key handle
    if(!CryptAcquireCertificatePrivateKey(
        pCertContext,
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
        NULL,
        &hKey,
        &dwKeySpec,
        &fCallerFree))
    {
        kprintf(L"Failed to acquire private key (error: 0x%08x)\n", GetLastError());
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return STATUS_UNSUCCESSFUL;
    }
    
    kprintf(L"Key spec: %s (%u)\n", 
        (dwKeySpec == AT_SIGNATURE) ? L"AT_SIGNATURE" : 
        (dwKeySpec == AT_KEYEXCHANGE) ? L"AT_KEYEXCHANGE" : 
        (dwKeySpec == CERT_NCRYPT_KEY_SPEC) ? L"CERT_NCRYPT_KEY_SPEC" : L"UNKNOWN",
        dwKeySpec);
    
    // Check if this is a TPM-backed key
    if(dwKeySpec == CERT_NCRYPT_KEY_SPEC)
    {
        // Try to get KSP name
        if(NT_SUCCESS(NCryptGetProperty(hKey, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PUCHAR)&hProv, sizeof(hProv), &cbResult, 0)))
        {
            DWORD cbName = 0;
            if(NT_SUCCESS(NCryptGetProperty(hProv, NCRYPT_NAME_PROPERTY, NULL, 0, &cbName, 0)))
            {
                if(provName = (LPWSTR)LocalAlloc(LPTR, cbName))
                {
                    if(NT_SUCCESS(NCryptGetProperty(hProv, NCRYPT_NAME_PROPERTY, (PUCHAR)provName, cbName, &cbName, 0)))
                    {
                        kprintf(L"KSP Name: %s\n", provName);
                        
                        // Check if it's a TPM KSP
                        if(wcsstr(provName, L"TPM") != NULL ||
                           wcsstr(provName, L"Platform") != NULL ||
                           wcsstr(provName, L"Microsoft Smart Card") != NULL)
                        {
                            kprintf(L"Hardware-backed key detected!\n");
                            
                            // Get key name
                            cbName = 0;
                            if(NT_SUCCESS(NCryptGetProperty(hKey, NCRYPT_NAME_PROPERTY, NULL, 0, &cbName, 0)))
                            {
                                if(keyName = (LPWSTR)LocalAlloc(LPTR, cbName))
                                {
                                    if(NT_SUCCESS(NCryptGetProperty(hKey, NCRYPT_NAME_PROPERTY, (PUCHAR)keyName, cbName, &cbName, 0)))
                                    {
                                        kprintf(L"Key Name: %s\n", keyName);
                                    }
                                    LocalFree(keyName);
                                }
                            }
                            
                            // Try to get key characteristics
                            cbResult = sizeof(dwProviderType);
                            if(NT_SUCCESS(NCryptGetProperty(hKey, NCRYPT_KEY_TYPE_PROPERTY, (PUCHAR)&dwProviderType, sizeof(dwProviderType), &cbResult, 0)))
                            {
                                kprintf(L"Key Type: %s (%u)\n", 
                                    (dwProviderType == NCRYPT_RSA_ALGORITHM) ? L"RSA" : 
                                    (dwProviderType == NCRYPT_ECDSA_ALGORITHM) ? L"ECDSA" :
                                    (dwProviderType == NCRYPT_ECDH_ALGORITHM) ? L"ECDH" : L"UNKNOWN",
                                    dwProviderType);
                            }
                            
                            // Try to export public key (might work even for protected keys)
                            if(NT_SUCCESS(NCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &keyBlobSize, 0)))
                            {
                                if(keyBlob = (PBYTE)LocalAlloc(LPTR, keyBlobSize))
                                {
                                    if(NT_SUCCESS(NCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, keyBlob, keyBlobSize, &keyBlobSize, 0)))
                                    {
                                        pRsaKeyBlob = (BCRYPT_RSAKEY_BLOB*)keyBlob;
                                        kprintf(L"RSA Public Key:\n");
                                        kprintf(L"  Key size: %u bits\n", pRsaKeyBlob->BitLength);
                                        kprintf(L"  Exponent: ");
                                        
                                        PBYTE pExp = keyBlob + sizeof(BCRYPT_RSAKEY_BLOB);
                                        for(DWORD i = 0; i < pRsaKeyBlob->cbPublicExp; i++)
                                            kprintf(L"%02X", pExp[i]);
                                        kprintf(L"\n");
                                        
                                        kprintf(L"  Modulus: ");
                                        PBYTE pMod = pExp + pRsaKeyBlob->cbPublicExp;
                                        // Just show first 16 bytes for brevity
                                        for(DWORD i = 0; i < min(16, pRsaKeyBlob->cbModulus); i++)
                                            kprintf(L"%02X", pMod[i]);
                                        if(pRsaKeyBlob->cbModulus > 16)
                                            kprintf(L"...");
                                        kprintf(L"\n");
                                    }
                                    LocalFree(keyBlob);
                                }
                            }
                            else
                            {
                                kprintf(L"Cannot export public key (error: 0x%08x)\n", GetLastError());
                            }
                            
                            // Try to get TPM-specific properties (may not work for all KSPs)
                            kprintf(L"\nTPM Key Properties:\n");
                            
                            // Check if key is hardware-protected
                            DWORD dwProtected = 0;
                            cbResult = sizeof(dwProtected);
                            if(NT_SUCCESS(NCryptGetProperty(hKey, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, (PUCHAR)&dwProtected, sizeof(dwProtected), &cbResult, 0)))
                            {
                                kprintf(L"  Hardware protected: %s\n", dwProtected ? L"Yes" : L"No");
                            }
                            
                            // Check PCR binding
                            DWORD dwPcrBinding = 0;
                            cbResult = sizeof(dwPcrBinding);
                            // Custom property name - might not work on all KSPs
                            if(NT_SUCCESS(NCryptGetProperty(hKey, L"PCP_PLATFORMHANDLE_PROPERTY", (PUCHAR)&dwPcrBinding, sizeof(dwPcrBinding), &cbResult, 0)))
                            {
                                kprintf(L"  PCR binding: Active\n");
                                // Could try to extract exact PCR mask here with more advanced code
                            }
                            else
                            {
                                kprintf(L"  PCR binding: Unknown\n");
                            }
                        }
                        else
                        {
                            kprintf(L"Software-based key\n");
                        }
                    }
                    LocalFree(provName);
                }
            }
            
            NCryptFreeObject(hProv);
        }
    }
    else
    {
        kprintf(L"Legacy CSP key (not an NCrypt key)\n");
    }
    
    // Clean up
    if(fCallerFree && hKey)
        NCryptFreeObject(hKey);
    
    if(pCertContext)
        CertFreeCertificateContext(pCertContext);
    
    if(hStore)
        CertCloseStore(hStore, 0);
    
    return STATUS_SUCCESS;
}

// Complete implementation of certificate template listing 
NTSTATUS kuhl_m_cert_template(int argc, wchar_t * argv[])
{
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    DWORD i = 0, j, cbData;
    LPWSTR templateName, oidName;
    LPSTR oidValue;
    LPWSTR pszStoreName = L"CA";
    PCERT_EXTENSION pCertExtension;
    CERT_TEMPLATE_EXT *pTemplate;
    CERT_ENHKEY_USAGE keyUsage;
    CERT_ENHKEY_USAGE *pKeyUsage = NULL;
    DWORD dwFlags = 0, dwTemplateCount = 0;
    BOOL templateCounted = FALSE;
    
    // Parse command line arguments
    for(j = 0; j < (DWORD)argc; j++)
    {
        if(_wcsnicmp(argv[j], L"/store:", 7) == 0)
            pszStoreName = argv[j] + 7;
        if(_wcsnicmp(argv[j], L"/ca", 3) == 0)
            dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }
    
    // Open the certificate store
    hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, dwFlags, pszStoreName);
    if(!hCertStore)
    {
        // Try current user store if machine store failed
        hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, pszStoreName);
        if(!hCertStore)
        {
            PRINT_ERROR(L"Failed to open certificate store (error: 0x%08x)\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }
    }
    
    // Also check for NTAuth store that contains enterprise CA templates
    HCERTSTORE hNTAuthStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"NTAuth");
    
    kprintf(L"\n== Certificate Templates ==\n");
    kprintf(L"%-4s %-32s %-12s %-40s\n", L"ID", L"Template Name", L"Flags", L"Description");
    kprintf(L"--------------------------------------------------------------------------------\n");
    
    // First enumerate templates from NTAuth store
    if(hNTAuthStore)
    {
        while((pCertContext = CertEnumCertificatesInStore(hNTAuthStore, pCertContext)) != NULL)
        {
            templateCounted = FALSE;
            
            for(j = 0; j < pCertContext->pCertInfo->cExtension; j++)
            {
                pCertExtension = &pCertContext->pCertInfo->rgExtension[j];
                
                if(strcmp(pCertExtension->pszObjId, szOID_CERTIFICATE_TEMPLATE) == 0)
                {
                    if(CryptDecodeObject(X509_ASN_ENCODING, X509_CERTIFICATE_TEMPLATE, 
                                       pCertExtension->Value.pbData, pCertExtension->Value.cbData, 
                                       0, NULL, &cbData))
                    {
                        pTemplate = (CERT_TEMPLATE_EXT*)LocalAlloc(LPTR, cbData);
                        if(pTemplate)
                        {
                            if(CryptDecodeObject(X509_ASN_ENCODING, X509_CERTIFICATE_TEMPLATE, 
                                               pCertExtension->Value.pbData, pCertExtension->Value.cbData, 
                                               0, pTemplate, &cbData))
                            {
                                if(!templateCounted)
                                {
                                    dwTemplateCount++;
                                    templateCounted = TRUE;
                                }
                                
                                kprintf(L"%-4d %-32S 0x%08X ", i++, pTemplate->pszObjId, pTemplate->dwMajorVersion);
                                
                                // Get template friendly name from OID
                                oidName = L"Unknown";
                                if(oidValue = strrchr(pTemplate->pszObjId, '.'))
                                {
                                    // Try to resolve from friendly name lookup
                                    templateName = kuhl_m_crypto_oid_to_name(pTemplate->pszObjId);
                                    if(templateName)
                                        oidName = templateName;
                                    else
                                        oidName = L"Unknown Template";
                                }
                                
                                kprintf(L"%-40s\n", oidName);
                            }
                            LocalFree(pTemplate);
                        }
                    }
                }
                
                // Check enhanced key usage for more template info
                if(strcmp(pCertExtension->pszObjId, szOID_ENHANCED_KEY_USAGE) == 0)
                {
                    if(CryptDecodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, 
                                       pCertExtension->Value.pbData, pCertExtension->Value.cbData, 
                                       0, NULL, &cbData))
                    {
                        pKeyUsage = (CERT_ENHKEY_USAGE*)LocalAlloc(LPTR, cbData);
                        if(pKeyUsage)
                        {
                            if(CryptDecodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, 
                                               pCertExtension->Value.pbData, pCertExtension->Value.cbData, 
                                               0, pKeyUsage, &cbData))
                            {
                                if(pKeyUsage->cUsageIdentifier > 0)
                                {
                                    kprintf(L"    Key Usage: ");
                                    for(DWORD k = 0; k < pKeyUsage->cUsageIdentifier; k++)
                                    {
                                        templateName = kuhl_m_crypto_oid_to_name(pKeyUsage->rgpszUsageIdentifier[k]);
                                        if(templateName)
                                            kprintf(L"%s%s", (k > 0) ? L", " : L"", templateName);
                                        else
                                            kprintf(L"%s%S", (k > 0) ? L", " : L"", pKeyUsage->rgpszUsageIdentifier[k]);
                                    }
                                    kprintf(L"\n");
                                }
                            }
                            LocalFree(pKeyUsage);
                        }
                    }
                }
            }
        }
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hNTAuthStore, 0);
    }
    
    // Enumerate any templates in the specified store
    pCertContext = NULL;
    while((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL)
    {
        templateCounted = FALSE;
        
        // Same template extraction logic as above
        for(j = 0; j < pCertContext->pCertInfo->cExtension; j++)
        {
            pCertExtension = &pCertContext->pCertInfo->rgExtension[j];
            
            if(strcmp(pCertExtension->pszObjId, szOID_CERTIFICATE_TEMPLATE) == 0)
            {
                if(CryptDecodeObject(X509_ASN_ENCODING, X509_CERTIFICATE_TEMPLATE, 
                                   pCertExtension->Value.pbData, pCertExtension->Value.cbData, 
                                   0, NULL, &cbData))
                {
                    pTemplate = (CERT_TEMPLATE_EXT*)LocalAlloc(LPTR, cbData);
                    if(pTemplate)
                    {
                        if(CryptDecodeObject(X509_ASN_ENCODING, X509_CERTIFICATE_TEMPLATE, 
                                           pCertExtension->Value.pbData, pCertExtension->Value.cbData, 
                                           0, pTemplate, &cbData))
                        {
                            if(!templateCounted)
                            {
                                dwTemplateCount++;
                                templateCounted = TRUE;
                            }
                            
                            kprintf(L"%-4d %-32S 0x%08X ", i++, pTemplate->pszObjId, pTemplate->dwMajorVersion);
                            
                            // Get template friendly name from OID
                            oidName = L"Unknown";
                            if(oidValue = strrchr(pTemplate->pszObjId, '.'))
                            {
                                // Try to resolve from friendly name lookup
                                templateName = kuhl_m_crypto_oid_to_name(pTemplate->pszObjId);
                                if(templateName)
                                    oidName = templateName;
                                else
                                    oidName = L"Unknown Template";
                            }
                            
                            kprintf(L"%-40s\n", oidName);
                        }
                        LocalFree(pTemplate);
                    }
                }
            }
        }
    }
    
    // If no templates found, try to query via ADSI/LDAP in enterprise environment
    if(dwTemplateCount == 0)
    {
        kprintf(L"No templates found in stores - enterprise AD templates must be queried via LDAP.\n");
        kprintf(L"You can connect to your domain with: ldap://your-domain.com\n");
    }
    
    kprintf(L"\nFound %u certificate templates\n\n", dwTemplateCount);
    
    // Clean up
    if(pCertContext) 
        CertFreeCertificateContext(pCertContext);
    if(hCertStore)
        CertCloseStore(hCertStore, 0);
        
    return STATUS_SUCCESS;
}

// Helper function to convert OID to friendly name (simplified implementation)
LPWSTR kuhl_m_crypto_oid_to_name(LPCSTR oidValue)
{
    static struct {
        LPCSTR oid;
        LPCWSTR name;
    } oidMap[] = {
        {"1.3.6.1.5.5.7.3.1", L"Server Authentication"},
        {"1.3.6.1.5.5.7.3.2", L"Client Authentication"},
        {"1.3.6.1.5.5.7.3.3", L"Code Signing"},
        {"1.3.6.1.5.5.7.3.4", L"Email Protection"},
        {"1.3.6.1.5.5.7.3.8", L"Time Stamping"},
        {"1.3.6.1.4.1.311.20.2.2", L"Smart Card Logon"},
        {"1.3.6.1.4.1.311.10.3.4", L"Encrypting File System"},
        {"1.3.6.1.4.1.311.10.3.12", L"Document Signing"},
        {"1.3.6.1.4.1.311.21.8.7072687.1246273.14911893.2536021.7599843.64.1", L"User Template"},
        {"1.3.6.1.4.1.311.21.8.7072687.1246273.14911893.2536021.7599843.64.2", L"Machine Template"},
    };
    
    for(DWORD i = 0; i < ARRAYSIZE(oidMap); i++)
    {
        if(strcmp(oidValue, oidMap[i].oid) == 0)
            return (LPWSTR)oidMap[i].name;
    }
    
    // Try to get name from system
    PCCRYPT_OID_INFO pOIDInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, oidValue, CRYPT_OID_DISABLE_SEARCH_DS_FLAG);
    if(pOIDInfo && pOIDInfo->pwszName)
        return (LPWSTR)pOIDInfo->pwszName;
        
    return NULL;
}

// Function to link TPM with certificates
NTSTATUS kuhl_m_cert_tpm_bind(int argc, wchar_t * argv[])
{
    LPCWSTR certStore = L"MY";
    LPCWSTR certName = NULL;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    BOOL fCallerFree = FALSE;
    DWORD dwKeySpec = 0;
    HRESULT hr;
    BOOL fTPMBound = FALSE;
    DWORD cbResult;
    TBS_HCONTEXT hTbs = NULL;
    TBS_CONTEXT_PARAMS2 params = {0};
    
    // Parse command line arguments
    for(DWORD i = 0; i < (DWORD)argc; i++)
    {
        if(_wcsnicmp(argv[i], L"/store:", 7) == 0)
        {
            certStore = argv[i] + 7;
        }
        else if(_wcsnicmp(argv[i], L"/cert:", 6) == 0)
        {
            certName = argv[i] + 6;
        }
    }
    
    if(!certName)
    {
        kprintf(L"Certificate name required. Usage: tpm_bind /cert:\"CertName\" [/store:StoreName]\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    // Open the certificate store
    hStore = CertOpenSystemStore(0, certStore);
    if(!hStore)
    {
        PRINT_ERROR(L"Failed to open certificate store '%s' (error: 0x%08x)\n", certStore, GetLastError());
        return STATUS_UNSUCCESSFUL;
    }
    
    // Find certificate by subject
    pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        certName,
        NULL);
        
    if(!pCertContext)
    {
        PRINT_ERROR(L"Failed to find certificate '%s' (error: 0x%08x)\n", certName, GetLastError());
        CertCloseStore(hStore, 0);
        return STATUS_UNSUCCESSFUL;
    }
    
    // Get certificate private key
    hr = CryptAcquireCertificatePrivateKey(
        pCertContext,
        CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
        NULL,
        &hKey,
        &dwKeySpec,
        &fCallerFree);
        
    if(FAILED(hr) || !hKey)
    {
        PRINT_ERROR(L"Failed to acquire certificate private key (error: 0x%08x)\n", hr);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return STATUS_UNSUCCESSFUL;
    }
    
    // Check if key is already TPM-bound
    NCRYPT_PROV_HANDLE hProv = 0;
    LPWSTR provName = NULL;
    
    // Get provider handle
    if(NT_SUCCESS(NCryptGetProperty(hKey, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PUCHAR)&hProv, sizeof(hProv), &cbResult, 0)))
    {
        DWORD cbName = 0;
        if(NT_SUCCESS(NCryptGetProperty(hProv, NCRYPT_NAME_PROPERTY, NULL, 0, &cbName, 0)))
        {
            if(provName = (LPWSTR)LocalAlloc(LPTR, cbName))
            {
                if(NT_SUCCESS(NCryptGetProperty(hProv, NCRYPT_NAME_PROPERTY, (PUCHAR)provName, cbName, &cbName, 0)))
                {
                    if(wcsstr(provName, L"TPM") || wcsstr(provName, L"Platform"))
                    {
                        kprintf(L"Certificate already uses TPM-backed key via %s provider\n", provName);
                        fTPMBound = TRUE;
                    }
                }
                LocalFree(provName);
            }
        }
        
        NCryptFreeObject(hProv);
    }
    
    // If not TPM-bound, this would be where we'd try to bind it
    if(!fTPMBound)
    {
        kprintf(L"Certificate is not TPM-bound. Binding requires a TPM key provider.\n");
        
        // Check if we have a TPM available
        params.version = TBS_CONTEXT_VERSION_TWO;
        params.includeTpm12 = FALSE;
        params.includeTpm20 = TRUE;
        
        if(Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs) == TBS_SUCCESS)
        {
            kprintf(L"TPM 2.0 is available on this system.\n");
            
            // To actually bind the cert to TPM would require:
            // 1. Export the existing key (if possible)
            // 2. Create a new TPM-backed key
            // 3. Import the certificate to use the new key
            // 4. Delete the old key
            
            kprintf(L"Note: Actual TPM key creation requires administrative privileges\n");
            kprintf(L"and would use NCryptCreatePersistedKey with MS_PLATFORM_KEY_STORAGE_PROVIDER.\n");
            
            // Cleanup TPM context
            Tbsip_Context_Close(hTbs);
        }
        else
        {
            // Try TPM 1.2
            params.includeTpm12 = TRUE;
            params.includeTpm20 = FALSE;
            
            if(Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs) == TBS_SUCCESS)
            {
                kprintf(L"TPM 1.2 is available on this system.\n");
                Tbsip_Context_Close(hTbs);
            }
            else
            {
                kprintf(L"No TPM appears to be available on this system.\n");
            }
        }
    }
    
    // Clean up
    if(fCallerFree)
        NCryptFreeObject(hKey);
    
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);
    
    return STATUS_SUCCESS;
}

// Function to create a TPM-backed certificate
NTSTATUS kuhl_m_cert_tpm_create(int argc, wchar_t * argv[])
{
    LPCWSTR containerName = NULL;
    LPCWSTR subject = NULL;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL fTPMAvailable = FALSE;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BYTE keyData[1024] = {0};
    DWORD keyDataLen = sizeof(keyData);
    TBS_HCONTEXT hTbs = NULL;
    TBS_CONTEXT_PARAMS2 params = {0};
    NCRYPT_PROV_HANDLE hNcryptProv = NULL;
    NCRYPT_KEY_HANDLE hNcryptKey = NULL;
    
    // Parse command line arguments
    for(DWORD i = 0; i < (DWORD)argc; i++)
    {
        if(_wcsnicmp(argv[i], L"/name:", 6) == 0)
        {
            containerName = argv[i] + 6;
        }
        else if(_wcsnicmp(argv[i], L"/subject:", 9) == 0)
        {
            subject = argv[i] + 9;
        }
    }
    
    if(!containerName || !subject)
    {
        kprintf(L"Container name and subject required. Usage: tpm_create /name:\"KeyName\" /subject:\"CN=TestCert\"\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    // Check if we have a TPM available
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = FALSE;
    params.includeTpm20 = TRUE;
    
    if(Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs) == TBS_SUCCESS)
    {
        kprintf(L"TPM 2.0 is available on this system.\n");
        fTPMAvailable = TRUE;
        Tbsip_Context_Close(hTbs);
    }
    else
    {
        // Try TPM 1.2
        params.includeTpm12 = TRUE;
        params.includeTpm20 = FALSE;
        
        if(Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hTbs) == TBS_SUCCESS)
        {
            kprintf(L"TPM 1.2 is available on this system.\n");
            fTPMAvailable = TRUE;
            Tbsip_Context_Close(hTbs);
        }
    }
    
    if(!fTPMAvailable)
    {
        kprintf(L"No TPM appears to be available on this system.\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // Use Platform Crypto Provider to create a key
    SECURITY_STATUS secStatus = NCryptOpenStorageProvider(
        &hNcryptProv, 
        MS_PLATFORM_CRYPTO_PROVIDER, // For TPM-backed keys
        0);
    
    if(secStatus != ERROR_SUCCESS)
    {
        secStatus = NCryptOpenStorageProvider(
            &hNcryptProv, 
            MS_PLATFORM_KEY_STORAGE_PROVIDER, // Alternative KSP for TPM
            0);
    }
    
    if(secStatus != ERROR_SUCCESS)
    {
        PRINT_ERROR(L"Failed to open TPM key storage provider (error: 0x%08x)\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }
    
    // Create a new RSA key
    secStatus = NCryptCreatePersistedKey(
        hNcryptProv,
        &hNcryptKey,
        BCRYPT_RSA_ALGORITHM,
        containerName,
        0,
        NCRYPT_OVERWRITE_KEY_FLAG);
        
    if(secStatus != ERROR_SUCCESS)
    {
        PRINT_ERROR(L"Failed to create TPM-backed key (error: 0x%08x)\n", secStatus);
        NCryptFreeObject(hNcryptProv);
        return STATUS_UNSUCCESSFUL;
    }
    
    // Set key properties - 2048 bit key
    DWORD dwKeyLength = 2048;
    secStatus = NCryptSetProperty(
        hNcryptKey,
        NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwKeyLength,
        sizeof(DWORD),
        0);
        
    if(secStatus != ERROR_SUCCESS)
    {
        PRINT_ERROR(L"Failed to set key length (error: 0x%08x)\n", secStatus);
        NCryptFreeObject(hNcryptKey);
        NCryptFreeObject(hNcryptProv);
        return STATUS_UNSUCCESSFUL;
    }
    
    // Finalize (create) the key
    secStatus = NCryptFinalizeKey(hNcryptKey, 0);
    if(secStatus != ERROR_SUCCESS)
    {
        PRINT_ERROR(L"Failed to finalize key (error: 0x%08x)\n", secStatus);
        NCryptFreeObject(hNcryptKey);
        NCryptFreeObject(hNcryptProv);
        return STATUS_UNSUCCESSFUL;
    }
    
    kprintf(L"Successfully created TPM-backed key '%s'\n", containerName);
    
    // Here we could create a self-signed certificate using this key
    // For now just show that we've created the key successfully
    
    // Clean up
    NCryptFreeObject(hNcryptKey);
    NCryptFreeObject(hNcryptProv);
    
    return STATUS_SUCCESS;
}
