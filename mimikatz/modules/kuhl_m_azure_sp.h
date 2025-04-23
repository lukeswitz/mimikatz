/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m_azure.h"

BOOL kuhl_m_azure_sp_create(LPCWSTR szToken, LPCWSTR szName, LPCWSTR szCertPath, LPWSTR* pszAppId, LPWSTR* pszObjectId);
BOOL kuhl_m_azure_sp_addRole(LPCWSTR szToken, LPCWSTR szObjectId, LPCWSTR szRoleId);
