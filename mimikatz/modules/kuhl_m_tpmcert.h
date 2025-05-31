#pragma once
#include "kuhl_m.h"
#include <wincrypt.h>
#include <tbs.h>
#include <ncrypt.h>
#include <bcrypt.h>

// TPM algorithm defines
#define TPM_ALG_SHA1    0x0004
#define TPM_ALG_SHA256  0x000B
#define TPM_ALG_SHA384  0x000C
#define TPM_ALG_SHA512  0x000D

// TPM features
NTSTATUS kuhl_m_tpm_info(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_pcrs(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_nvlist(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_quote(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_attestation(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_seal(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_unseal(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_eventlog(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_policy(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tpm_keymigration(int argc, wchar_t * argv[]);

// TPM Policy file definitions
#define TPM_POLICY_FILE_MAGIC    0x4D505450  // "PTPM"
#define TPM_POLICY_FILE_VERSION  1

typedef struct _TPM_POLICY_FILE {
    DWORD Magic;           // Magic identifier "PTPM"
    DWORD Version;         // Policy format version
    DWORD PcrMask;         // Mask of PCRs included in policy
    BOOL IsTpm20;          // TRUE for TPM 2.0, FALSE for TPM 1.2
    FILETIME CreationTime; // Policy creation time
    BYTE Reserved[12];     // Reserved for future use
} TPM_POLICY_FILE, *PTPM_POLICY_FILE;

// TPM Policy functions
DWORD kuhl_m_tpm_policy_create(TBS_HCONTEXT hTbs, LPCWSTR policyFile, DWORD dwPcrMask, BOOL isTpm20);
DWORD kuhl_m_tpm_policy_read(TBS_HCONTEXT hTbs, LPCWSTR policyFile, BOOL currentIsTpm20);
DWORD kuhl_m_tpm_policy_apply(TBS_HCONTEXT hTbs, LPCWSTR policyFile, LPCWSTR keyName, BOOL isTpm20);
DWORD kuhl_m_tpm_policy_validate(TBS_HCONTEXT hTbs, LPCWSTR policyFile, LPCWSTR keyName, BOOL currentIsTpm20);
DWORD kuhl_m_tpm_policy_readBlob(LPCWSTR policyFile, PTPM_POLICY_FILE pHeader, PBYTE* ppBlob, PDWORD pBlobSize);

// Certificate features
NTSTATUS kuhl_m_cert_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_export(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_import(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_extractkey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_validate(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_revocation(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_expiry(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_csr(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_autoenroll(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_usage(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_truststore(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_smartcard(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_template(int argc, wchar_t * argv[]);

// Combined TPM and Certificate features
NTSTATUS kuhl_m_cert_tpm_extract(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_tpm_bind(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_cert_tpm_create(int argc, wchar_t * argv[]);

// Helper functions
LPWSTR GetTpmManufacturerName(UINT32 manufacturerId);
LPWSTR kuhl_m_crypto_oid_to_name(LPCSTR oidValue);
