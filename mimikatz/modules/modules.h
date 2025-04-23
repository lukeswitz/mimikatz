/*	Benjamin DELPY `gentilkiwi`
	Laboratoire d'Expertise et de Recherche en Forensic Informatique
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence Pro - Copyright (C) 2023
*/
#pragma once
#include "kuhl_m.h"
#include "kuhl_m_standard.h"
#include "kuhl_m_crypto.h"
#include "kuhl_m_sekurlsa.h"
#include "kuhl_m_kerberos.h"
#include "kuhl_m_ngc.h"
#include "kuhl_m_privilege.h"
#include "kuhl_m_process.h"
#include "kuhl_m_service.h"
#include "kuhl_m_lsadump.h"
#include "kuhl_m_ts.h"
#include "kuhl_m_event.h"
#include "kuhl_m_misc.h"
#include "kuhl_m_token.h"
#include "kuhl_m_vault.h"
#include "kuhl_m_minesweeper.h"
#include "kuhl_m_sid.h"
#include "kuhl_m_iis.h"
#include "kuhl_m_rpc.h"
#include "kuhl_m_busylight.h"
#include "kuhl_m_sysenvvalue.h"
#include "kuhl_m_dpapi.h"
#include "kuhl_m_sr98.h"
#include "kuhl_m_rdm.h"
#include "kuhl_m_acr.h"
#include "kuhl_m_sysproc.h"
#include "kuhl_m_hash.h"
#include "kuhl_m_tpm.h"
#include "kuhl_m_tpmcert.h"

const KUHL_M * KUHL_M_MODULES[] = {
	&kuhl_m_standard,
	&kuhl_m_crypto,
	&kuhl_m_sekurlsa,
	&kuhl_m_kerberos,
	&kuhl_m_ngc,
	&kuhl_m_privilege,
	&kuhl_m_process,
	&kuhl_m_service,
	&kuhl_m_lsadump,
	&kuhl_m_ts,
	&kuhl_m_event,
	&kuhl_m_misc,
	&kuhl_m_token,
	&kuhl_m_vault,
	&kuhl_m_minesweeper,
	&kuhl_m_sid,
	&kuhl_m_iis,
	&kuhl_m_rpc,
	&kuhl_m_busylight,
	&kuhl_m_sysenvvalue,
	&kuhl_m_dpapi,
	&kuhl_m_sr98,
	&kuhl_m_rdm,
	&kuhl_m_acr,
	&kuhl_m_sysproc,
	&kuhl_m_hash,
	&kuhl_m_tpm,
	&kuhl_m_tpmcert,
};

const unsigned int KUHL_M_MODULES_COUNT = ARRAYSIZE(KUHL_M_MODULES);