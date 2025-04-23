#pragma once
#include "kuhl_m.h"
#include <wincrypt.h>
#include <tbs.h> // For TPM Base Services API

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
