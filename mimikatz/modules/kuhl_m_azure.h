/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../../modules/kull_m_file.h"
#include "../../modules/kull_m_string.h"
#include "../../modules/kull_m_xml.h"
#include "../../modules/kull_m_registry.h"
#include "../../modules/kull_m_crypto.h"
#include "../../modules/kull_m_net.h"
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <rpc.h>

const KUHL_M kuhl_m_azure;

// Original functions
NTSTATUS kuhl_m_azure_tokens(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_cli(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_powershell(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_accesstoken(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_list(int argc, wchar_t * argv[]);

// Azure AD specific functions
NTSTATUS kuhl_m_azure_ad_users(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_ad_groups(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_ad_apps(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_ad_devicecode(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_ad_serviceprincipal(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_ad_prt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_ad_jwt(int argc, wchar_t * argv[]);

// AD-equivalent functions
NTSTATUS kuhl_m_azure_adconnect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_adfs(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_prt_ticket(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_certificate(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_backdoor(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_privesc(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_ropc(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_conditional_access(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_azure_persistence(int argc, wchar_t * argv[]);

// Azure HTTP helper functions
BOOL kuhl_m_azure_http_request(LPCWSTR szHost, INTERNET_PORT nPort, BOOL bIsHttps, LPCWSTR szUrl, LPCWSTR szMethod, LPCWSTR szHeaders, LPCBYTE pbData, DWORD cbData, PBYTE* ppbOutData, PDWORD pcbOutData);
BOOL kuhl_m_azure_http_apiRequest(LPCWSTR szBase, LPCWSTR szEndpoint, LPCWSTR szAccessToken, LPCWSTR szMethod, LPCWSTR szData, PBYTE* ppbOutData, PDWORD pcbOutData);
BOOL kuhl_m_azure_parse_jwt(LPCWSTR szJwt, PBYTE* ppbHeader, PDWORD pcbHeader, PBYTE* ppbPayload, PDWORD pcbPayload);

// Azure endpoints and constants
#define AZURE_AUTH_URL_WORLDWIDE L"login.microsoftonline.com"
#define AZURE_AUTH_URL_CHINA L"login.chinacloudapi.cn"
#define AZURE_AUTH_URL_GERMANY L"login.microsoftonline.de"
#define AZURE_AUTH_URL_US_GOV L"login.microsoftonline.us"

#define AZURE_GRAPH_API_VERSION L"v1.0"
#define AZURE_GRAPH_API_URL L"graph.microsoft.com"

// Azure AD Connect constants
#define AZURE_ADCONNECT_DB L"ADSync"

// PRT-related constants
#define PRT_REQUEST_URI L"/common/oauth2/token"
#define PRT_COOKIE_NAME L"x-ms-RefreshTokenCredential"

// Azure JWT token security constants
#define JWT_ALG_NONE   "none"
#define JWT_ALG_HS256  "HS256"
#define JWT_ALG_RS256  "RS256"

// Azure Role constants (matching on-premise roles)
#define AZURE_ROLE_GLOBAL_ADMIN L"62e90394-69f5-4237-9190-012177145e10"
#define AZURE_ROLE_USER_ADMIN L"fe930be7-5e62-47db-91af-98c3a49a38b1"
#define AZURE_ROLE_EXCHANGE_ADMIN L"29232cdf-9323-42fd-ade2-1d097af3e4de"
#define AZURE_ROLE_APP_ADMIN L"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"

// Data structures
typedef struct _AZURE_CLI_CRED {
    LPWSTR accessToken;
    LPWSTR expiresOn;
    LPWSTR subscription;
    LPWSTR tenantId;
    LPWSTR userId;
} AZURE_CLI_CRED, *PAZURE_CLI_CRED;

typedef struct _AZURE_JWT_TOKEN {
    LPWSTR rawToken;
    PBYTE header;       // JSON decoded header
    DWORD cbHeader;
    PBYTE payload;      // JSON decoded payload
    DWORD cbPayload;
    LPWSTR signature;   // Base64Url encoded signature
} AZURE_JWT_TOKEN, *PAZURE_JWT_TOKEN;

// Azure AD user structure
typedef struct _AZURE_AD_USER {
    LPWSTR id;
    LPWSTR userPrincipalName;
    LPWSTR displayName;
    LPWSTR mail;
    LPWSTR jobTitle;
    BOOL accountEnabled;
} AZURE_AD_USER, *PAZURE_AD_USER;

// Azure AD group structure
typedef struct _AZURE_AD_GROUP {
    LPWSTR id;
    LPWSTR displayName;
    LPWSTR description;
    LPWSTR mailNickname;
    BOOL securityEnabled;
    BOOL mailEnabled;
} AZURE_AD_GROUP, *PAZURE_AD_GROUP;

// Azure AD app structure
typedef struct _AZURE_AD_APP {
    LPWSTR appId;
    LPWSTR displayName;
    LPWSTR identifierUris;
    LPWSTR signInAudience;
    LPWSTR publisherDomain;
} AZURE_AD_APP, *PAZURE_AD_APP;

// Azure AD service principal structure
typedef struct _AZURE_AD_SERVICE_PRINCIPAL {
    LPWSTR id;
    LPWSTR appId;
    LPWSTR displayName;
    LPWSTR servicePrincipalType;
    BOOL accountEnabled;
} AZURE_AD_SERVICE_PRINCIPAL, *PAZURE_AD_SERVICE_PRINCIPAL;

// Azure AD Connect credential structure
typedef struct _AZURE_ADCONNECT_CRED {
    LPWSTR domain;
    LPWSTR username;
    LPWSTR encryptedPassword;
    LPWSTR decryptedPassword;
} AZURE_ADCONNECT_CRED, *PAZURE_ADCONNECT_CRED;

// Azure AD PRT structure
typedef struct _AZURE_AD_PRT {
    LPWSTR cookie;
    LPWSTR decodedToken;
    LPWSTR upn;
    LPWSTR tid;
    LPWSTR deviceId;
    LPWSTR sessionKey;
    FILETIME expirationTime;
} AZURE_AD_PRT, *PAZURE_AD_PRT;

// Azure Conditional Access Policy structure
typedef struct _AZURE_CONDITIONAL_ACCESS_POLICY {
    LPWSTR id;
    LPWSTR displayName;
    BOOL state;
    LPWSTR conditions;  // JSON representation of conditions
    LPWSTR controls;    // JSON representation of controls
} AZURE_CONDITIONAL_ACCESS_POLICY, *PAZURE_CONDITIONAL_ACCESS_POLICY;

// JWT Token Header structure 
typedef struct _AZURE_JWT_HEADER {
    LPSTR typ;
    LPSTR alg;
    LPSTR kid;
    LPSTR x5t;
} AZURE_JWT_HEADER, *PAZURE_JWT_HEADER;

// JWT Token Claims structure
typedef struct _AZURE_JWT_CLAIMS {
    LPSTR iss;
    LPSTR sub;
    LPSTR aud;
    __time64_t nbf;
    __time64_t exp;
    __time64_t iat;
    LPSTR tid;
    LPSTR upn;
    LPSTR unique_name;
    LPSTR scp;
} AZURE_JWT_CLAIMS, *PAZURE_JWT_CLAIMS;

#define PRT_SESSION_KEY_SIZE 32
