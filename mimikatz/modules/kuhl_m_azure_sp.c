/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_azure_sp.h"

// Create a new service principal with a certificate for authentication
BOOL kuhl_m_azure_sp_create(LPCWSTR szToken, LPCWSTR szName, LPCWSTR szCertPath, LPWSTR* pszAppId, LPWSTR* pszObjectId)
{
	BOOL status = FALSE;
	WCHAR szUrl[MAX_PATH];
	WCHAR szRequestData[4096];
	PBYTE pbResponse = NULL, pbCert = NULL;
	DWORD cbResponse = 0, cbCert = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	WCHAR szCertificate[4096] = {0}; // Base64 encoded cert
	WCHAR szKeyId[64] = {0};
	
	*pszAppId = NULL;
	*pszObjectId = NULL;
	
	// Generate GUID for key ID
	GUID keyGuid;
	if(UuidCreate(&keyGuid) != RPC_S_OK)
	{
		PRINT_ERROR(L"Failed to create UUID for key ID\n");
		return FALSE;
	}
	
	// Format key ID as string
	swprintf_s(szKeyId, ARRAYSIZE(szKeyId), L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		keyGuid.Data1, keyGuid.Data2, keyGuid.Data3,
		keyGuid.Data4[0], keyGuid.Data4[1], keyGuid.Data4[2], keyGuid.Data4[3],
		keyGuid.Data4[4], keyGuid.Data4[5], keyGuid.Data4[6], keyGuid.Data4[7]);
	
	// Load certificate from file or create a new self-signed one
	if(szCertPath)
	{
		// Load certificate from file
		kprintf(L"[*] Loading certificate from: %s\n", szCertPath);
		
		if(kull_m_file_readData(szCertPath, &pbCert, &cbCert))
		{
			// Load certificate context
			pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbCert, cbCert);
			if(!pCertContext)
			{
				PRINT_ERROR(L"Failed to create certificate context (0x%08x)\n", GetLastError());
				LocalFree(pbCert);
				return FALSE;
			}
		}
		else
		{
			PRINT_ERROR(L"Failed to read certificate file\n");
			return FALSE;
		}
	}
	else
	{
		// Create a new self-signed certificate
		kprintf(L"[*] No certificate provided, creating a new self-signed certificate\n");
		
		// In a real implementation, we would create a self-signed cert here
		// For simplicity, we'll return an error
		PRINT_ERROR(L"Certificate creation not implemented - please provide a certificate file\n");
		return FALSE;
	}
	
	// Base64 encode the certificate
	DWORD dwEncodedLen = 0;
	if(CryptBinaryToString(pbCert, cbCert, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwEncodedLen))
	{
		if(CryptBinaryToString(pbCert, cbCert, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, szCertificate, &dwEncodedLen))
		{
			kprintf(L"[+] Certificate encoded successfully\n");
		}
		else
		{
			PRINT_ERROR(L"CryptBinaryToString failed (0x%08x)\n", GetLastError());
			CertFreeCertificateContext(pCertContext);
			LocalFree(pbCert);
			return FALSE;
		}
	}
	else
	{
		PRINT_ERROR(L"CryptBinaryToString (length) failed (0x%08x)\n", GetLastError());
		CertFreeCertificateContext(pCertContext);
		LocalFree(pbCert);
		return FALSE;
	}
	
	// Step 1: Create an application
	kprintf(L"[*] Creating new Azure AD application: %s\n", szName);
	
	// Construct URL for application creation
	wcscpy_s(szUrl, ARRAYSIZE(szUrl), L"/v1.0/applications");
	
	// Construct request data for application creation with certificate key
	swprintf_s(szRequestData, ARRAYSIZE(szRequestData),
		L"{\"displayName\":\"%s\",\"signInAudience\":\"AzureADMyOrg\",\"keyCredentials\":[{\"customKeyIdentifier\":\"\",\"endDateTime\":\"2099-12-31T00:00:00Z\",\"keyId\":\"%s\",\"startDateTime\":\"2023-01-01T00:00:00Z\",\"type\":\"AsymmetricX509Cert\",\"usage\":\"Verify\",\"key\":\"%s\"}]}",
		szName, szKeyId, szCertificate);
	
	// Make API call to create application
	if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"POST", szRequestData, &pbResponse, &cbResponse))
	{
		kprintf(L"[+] Application created successfully\n");
		
		// Extract application ID
		LPSTR appIdStart = strstr((LPSTR)pbResponse, "\"appId\":\"");
		LPSTR objectIdStart = strstr((LPSTR)pbResponse, "\"id\":\"");
		
		if(appIdStart && objectIdStart)
		{
			appIdStart += 9; // Skip "\"appId\":\""
			LPSTR appIdEnd = strstr(appIdStart, "\"");
			
			objectIdStart += 6; // Skip "\"id\":\""
			LPSTR objectIdEnd = strstr(objectIdStart, "\"");
			
			if(appIdEnd && objectIdEnd)
			{
				size_t appIdLen = appIdEnd - appIdStart;
				size_t objectIdLen = objectIdEnd - objectIdStart;
				
				*pszAppId = (LPWSTR)LocalAlloc(LPTR, (appIdLen + 1) * sizeof(WCHAR));
				*pszObjectId = (LPWSTR)LocalAlloc(LPTR, (objectIdLen + 1) * sizeof(WCHAR));
				
				if(*pszAppId && *pszObjectId)
				{
					// Convert to wide string
					for(size_t i = 0; i < appIdLen; i++)
						(*pszAppId)[i] = (WCHAR)appIdStart[i];
					
					for(size_t i = 0; i < objectIdLen; i++)
						(*pszObjectId)[i] = (WCHAR)objectIdStart[i];
					
					kprintf(L"[+] Application ID: %s\n", *pszAppId);
					kprintf(L"[+] Object ID: %s\n", *pszObjectId);
					
					// Step 2: Create a service principal for the application
					kprintf(L"[*] Creating service principal for the application\n");
					
					// Free previous response
					LocalFree(pbResponse);
					pbResponse = NULL;
					
					// Construct URL for service principal creation
					wcscpy_s(szUrl, ARRAYSIZE(szUrl), L"/v1.0/servicePrincipals");
					
					// Construct request data for service principal creation
					swprintf_s(szRequestData, ARRAYSIZE(szRequestData), L"{\"appId\":\"%s\"}", *pszAppId);
					
					// Make API call to create service principal
					if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"POST", szRequestData, &pbResponse, &cbResponse))
					{
						kprintf(L"[+] Service principal created successfully\n");
						
						// Extract service principal ID
						LPSTR spIdStart = strstr((LPSTR)pbResponse, "\"id\":\"");
						if(spIdStart)
						{
							spIdStart += 6; // Skip "\"id\":\""
							LPSTR spIdEnd = strstr(spIdStart, "\"");
							
							if(spIdEnd)
							{
								size_t spIdLen = spIdEnd - spIdStart;
								LPWSTR spId = (LPWSTR)LocalAlloc(LPTR, (spIdLen + 1) * sizeof(WCHAR));
								
								if(spId)
								{
									// Convert to wide string
									for(size_t i = 0; i < spIdLen; i++)
										spId[i] = (WCHAR)spIdStart[i];
									
									kprintf(L"[+] Service Principal ID: %s\n", spId);
									
									// Output authentication instructions
									kprintf(L"\n[*] Service principal created successfully with certificate authentication\n");
									kprintf(L"[*] You can now authenticate using the certificate and the following identifiers:\n");
									kprintf(L"    Application ID: %s\n", *pszAppId);
									kprintf(L"    Tenant ID: (Your tenant ID)\n");
									kprintf(L"    Certificate: %s\n", szCertPath ? szCertPath : L"(Generated certificate)");
									
									status = TRUE;
									LocalFree(spId);
								}
							}
						}
					}
					else
					{
						PRINT_ERROR(L"Failed to create service principal\n");
					}
				}
			}
		}
		
		if(pbResponse)
			LocalFree(pbResponse);
	}
	else
	{
		PRINT_ERROR(L"Failed to create application\n");
	}
	
	// Clean up
	if(pCertContext)
		CertFreeCertificateContext(pCertContext);
	if(pbCert)
		LocalFree(pbCert);
	
	return status;
}

// Add directory role to service principal
BOOL kuhl_m_azure_sp_addRole(LPCWSTR szToken, LPCWSTR szObjectId, LPCWSTR szRoleId)
{
	BOOL status = FALSE;
	WCHAR szUrl[MAX_PATH];
	WCHAR szRequestData[1024];
	PBYTE pbResponse = NULL;
	DWORD cbResponse = 0;
	
	// Step 1: Get role template
	kprintf(L"[*] Getting directory role: %s\n", szRoleId);
	
	// Construct URL for role assignment
	swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/v1.0/directoryRoles/roleTemplateId=%s", szRoleId);
	
	// Make API call to get role
	if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"GET", NULL, &pbResponse, &cbResponse))
	{
		// Extract role ID
		LPSTR roleIdStart = strstr((LPSTR)pbResponse, "\"id\":\"");
		if(roleIdStart)
		{
			roleIdStart += 6; // Skip "\"id\":\""
			LPSTR roleIdEnd = strstr(roleIdStart, "\"");
			
			if(roleIdEnd)
			{
				size_t roleIdLen = roleIdEnd - roleIdStart;
				LPWSTR activeRoleId = (LPWSTR)LocalAlloc(LPTR, (roleIdLen + 1) * sizeof(WCHAR));
				
				if(activeRoleId)
				{
					// Convert to wide string
					for(size_t i = 0; i < roleIdLen; i++)
						activeRoleId[i] = (WCHAR)roleIdStart[i];
					
					kprintf(L"[+] Found active directory role ID: %s\n", activeRoleId);
					
					// Free previous response
					LocalFree(pbResponse);
					pbResponse = NULL;
					
					// Step 2: Add service principal to role
					kprintf(L"[*] Adding service principal to directory role\n");
					
					// Construct URL for role member addition
					swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/v1.0/directoryRoles/%s/members/$ref", activeRoleId);
					
					// Construct request data
					swprintf_s(szRequestData, ARRAYSIZE(szRequestData),
						L"{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/%s\"}",
						szObjectId);
					
					// Make API call to add role member
					if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"POST", szRequestData, &pbResponse, &cbResponse))
					{
						kprintf(L"[+] Service principal added to role successfully\n");
						status = TRUE;
					}
					else
					{
						PRINT_ERROR(L"Failed to add service principal to role\n");
					}
					
					LocalFree(activeRoleId);
				}
			}
		}
		else
		{
			// Role might not be active, try to activate it
			kprintf(L"[*] Role not active, activating directory role\n");
			
			// Free previous response
			LocalFree(pbResponse);
			pbResponse = NULL;
			
			// Construct URL for role activation
			wcscpy_s(szUrl, ARRAYSIZE(szUrl), L"/v1.0/directoryRoles");
			
			// Construct request data for role activation
			swprintf_s(szRequestData, ARRAYSIZE(szRequestData), L"{\"roleTemplateId\":\"%s\"}", szRoleId);
			
			// Make API call to activate role
			if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"POST", szRequestData, &pbResponse, &cbResponse))
			{
				kprintf(L"[+] Role activated successfully\n");
				
				// Extract active role ID
				LPSTR activeRoleIdStart = strstr((LPSTR)pbResponse, "\"id\":\"");
				if(activeRoleIdStart)
				{
					activeRoleIdStart += 6; // Skip "\"id\":\""
					LPSTR activeRoleIdEnd = strstr(activeRoleIdStart, "\"");
					
					if(activeRoleIdEnd)
					{
						size_t activeRoleIdLen = activeRoleIdEnd - activeRoleIdStart;
						LPWSTR activeRoleId = (LPWSTR)LocalAlloc(LPTR, (activeRoleIdLen + 1) * sizeof(WCHAR));
						
						if(activeRoleId)
						{
							// Convert to wide string
							for(size_t i = 0; i < activeRoleIdLen; i++)
								activeRoleId[i] = (WCHAR)activeRoleIdStart[i];
							
							kprintf(L"[+] Activated directory role ID: %s\n", activeRoleId);
							
							// Free previous response
							LocalFree(pbResponse);
							pbResponse = NULL;
							
							// Now add service principal to role
							kprintf(L"[*] Adding service principal to directory role\n");
							
							// Construct URL for role member addition
							swprintf_s(szUrl, ARRAYSIZE(szUrl), L"/v1.0/directoryRoles/%s/members/$ref", activeRoleId);
							
							// Construct request data
							swprintf_s(szRequestData, ARRAYSIZE(szRequestData),
								L"{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/%s\"}",
								szObjectId);
							
							// Make API call to add role member
							if(kuhl_m_azure_http_apiRequest(AZURE_GRAPH_API_URL, szUrl, szToken, L"POST", szRequestData, &pbResponse, &cbResponse))
							{
								kprintf(L"[+] Service principal added to role successfully\n");
								status = TRUE;
							}
							else
							{
								PRINT_ERROR(L"Failed to add service principal to role\n");
							}
							
							LocalFree(activeRoleId);
						}
					}
				}
			}
			else
			{
				PRINT_ERROR(L"Failed to activate role\n");
			}
		}
	}
	else
	{
		PRINT_ERROR(L"Failed to get directory role\n");
	}
	
	if(pbResponse)
		LocalFree(pbResponse);
	
	return status;
}
