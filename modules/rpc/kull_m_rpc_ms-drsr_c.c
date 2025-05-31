#include "kull_m_rpc_ms-drsr.h"

// TODO: Refactor architecture-specific code to reduce duplication
#if defined(_M_X64) || defined(_M_ARM64)
typedef struct _ms2Ddrsr_MIDL_TYPE_FORMAT_STRING {
	SHORT Pad;
	UCHAR Format[1757];
} ms2Ddrsr_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Ddrsr_MIDL_PROC_FORMAT_STRING {
	SHORT Pad;
	UCHAR Format[853];
} ms2Ddrsr_MIDL_PROC_FORMAT_STRING;
static const unsigned short drsuapi_FormatStringOffsetTable[] = {0, 60, 104, 134, 202, 258, 314, 370, 400, 468, 498, 528, 558, 626, 656, 686, 716, 784};

#if defined(_M_ARM64)
// ARM64 Implementation - Experimental
void IDL_DRS_ARM64_Init(void)
{
    // This function is reserved for ARM64-specific initialization
    // TODO: Validate format strings and offset tables on ARM64 hardware
    
    // Note: When testing on actual ARM64 hardware, some adjustments may be required
    // for proper pointer alignment and structure packing
}
#endif

#elif defined(_M_IX86)
typedef struct _ms2Ddrsr_MIDL_TYPE_FORMAT_STRING {
	SHORT Pad;
	UCHAR Format[1933];
} ms2Ddrsr_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Ddrsr_MIDL_PROC_FORMAT_STRING {
	SHORT Pad;
	UCHAR Format[817];
} ms2Ddrsr_MIDL_PROC_FORMAT_STRING;
static const unsigned short drsuapi_FormatStringOffsetTable[] = {0, 58, 100, 128, 194, 248, 302, 356, 384, 450, 478, 506, 534, 600, 628, 656, 684, 750};
#endif

extern const ms2Ddrsr_MIDL_TYPE_FORMAT_STRING ms2Ddrsr__MIDL_TypeFormatString;
extern const ms2Ddrsr_MIDL_PROC_FORMAT_STRING ms2Ddrsr__MIDL_ProcFormatString;
extern const MIDL_SERVER_INFO drsuapi_ServerInfo;

static const RPC_DISPATCH_FUNCTION drsuapi_table[] = {NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, NdrServerCall2, 0};
static const RPC_DISPATCH_TABLE drsuapi_v4_0_DispatchTable = {18, (RPC_DISPATCH_FUNCTION *) drsuapi_table};
static const RPC_SERVER_INTERFACE drsuapi___RpcServerInterface = {sizeof(RPC_SERVER_INTERFACE), {{0xe3514235, 0x4b06, 0x11d1, {0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}}, {4, 0}}, {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}}, (RPC_DISPATCH_TABLE *) &drsuapi_v4_0_DispatchTable, 0, 0, 0, &drsuapi_ServerInfo, 0x04000000};
static const RPC_CLIENT_INTERFACE drsuapi___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0xe3514235, 0x4b06, 0x11d1, {0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}}, {4, 0}}, {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
RPC_IF_HANDLE
	drsuapi_v4_0_s_ifspec = (RPC_IF_HANDLE) &drsuapi___RpcServerInterface,
	drsuapi_v4_0_c_ifspec = (RPC_IF_HANDLE) &drsuapi___RpcClientInterface;
static const NDR_RUNDOWN RundownRoutines[] = {SRV_DRS_HANDLE_rundown};
static const SERVER_ROUTINE drsuapi_ServerRoutineTable[] = {
	(SERVER_ROUTINE) SRV_IDL_DRSBind,
	(SERVER_ROUTINE) SRV_IDL_DRSUnbind,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_IDL_DRSGetNCChanges,
	(SERVER_ROUTINE) SRV_IDL_DRSUpdateRefs,
	(SERVER_ROUTINE) SRV_IDL_DRSReplicaAddNotImplemented,
	(SERVER_ROUTINE) SRV_IDL_DRSReplicaDelNotImplemented,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_IDL_DRSVerifyNames,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_IDL_DRSCrackNamesNotImplemented,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_OpnumNotImplemented,
	(SERVER_ROUTINE) SRV_IDL_DRSDomainControllerInfoNotImplemented,
	(SERVER_ROUTINE) SRV_IDL_DRSAddEntryNotImplemented,
};
static RPC_BINDING_HANDLE drsuapi__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC
	drsuapi_s_StubDesc = {(void *) &drsuapi___RpcServerInterface, MIDL_user_allocate, MIDL_user_free, 0, RundownRoutines, 0, 0, 0, ms2Ddrsr__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0},
	drsuapi_c_StubDesc = {(void *) &drsuapi___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &drsuapi__MIDL_AutoBindHandle, 0, 0, 0, 0, ms2Ddrsr__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};
static const MIDL_SERVER_INFO drsuapi_ServerInfo = {&drsuapi_s_StubDesc, drsuapi_ServerRoutineTable, ms2Ddrsr__MIDL_ProcFormatString.Format, drsuapi_FormatStringOffsetTable, 0, 0, 0, 0};
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054, 0x3, 0, 0, 0,};

#if defined(_M_X64) || defined(_M_ARM64)
ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs)
{
    ULONG status;
    
    status = (ULONG) NdrClientCall2(
        (PMIDL_STUB_DESC) &drsuapi_c_StubDesc, 
        (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[0], 
        rpc_handle, 
        puuidClientDsa, 
        pextClient, 
        ppextServer, 
        phDrs
    ).Simple;
    
    // TODO: Consider adding better error handling and logging here
    return status;
}

ULONG IDL_DRSUnbind(DRS_HANDLE *phDrs)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[60], phDrs).Simple;
}

ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut)
{
    return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[134], hDrs, dwInVersion, pmsgIn, pdwOutVersion, pmsgOut).Simple;
}

ULONG IDL_DRSReplicaAdd(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[258], hDrs, dwVersion, pmsgAdd).Simple;
}

ULONG IDL_DRSReplicaDel(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[314], hDrs, dwVersion, pmsgDel).Simple;
}

ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[558], hDrs, dwInVersion, pmsgIn, pdwOutVersion, pmsgOut).Simple;
}

ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[716], hDrs, dwInVersion, pmsgIn, pdwOutVersion, pmsgOut).Simple;
}

ULONG IDL_DRSAddEntry(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[784], hDrs, dwInVersion, pmsgIn, pdwOutVersion, pmsgOut).Simple;
}

// Additional DRS function for extended operations (not in original DRSR interface)
ULONG IDL_DRSExecuteKCC(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_KCC_EXECUTE *pmsgIn)
{
    ULONG status = STATUS_NOT_IMPLEMENTED;
    
    if (!hDrs || !pmsgIn)
        return ERROR_INVALID_PARAMETER;
        
    // Only version 1 is supported in this implementation
    if (dwInVersion != 1)
        return ERROR_REVISION_MISMATCH;
        
    // KCC execution typically requires specific privileges
    // This would call the appropriate RPC function if implemented
    // For now, this is a placeholder for future implementation
    
    // TODO: Implement actual KCC execution via appropriate RPC call
    // status = NdrClientCall2(...);
    
    return status;
}

// Advanced DRS function to get the domain replication topology information
ULONG DRS_GetTopology(DRS_HANDLE hDrs, LPWSTR siteName, PDRS_TOPOLOGY_INFO* ppTopologyInfo)
{
    ULONG status = ERROR_CALL_NOT_IMPLEMENTED;
    DRS_MSG_DCINFOREQ msgRequest = {0};
    DRS_MSG_DCINFOREPLY msgReply = {0};
    DWORD dwOutVersion = 0;
    
    if (!hDrs || !ppTopologyInfo)
        return ERROR_INVALID_PARAMETER;
    
    *ppTopologyInfo = NULL;
    
    // Set up the request for all DCs in the specified site
    msgRequest.V1.InfoLevel = 2; // Detailed info
    msgRequest.V1.Domain = siteName ? siteName : NULL;
    
    status = IDL_DRSDomainControllerInfo(
        hDrs,
        1, // Version 1 request
        &msgRequest,
        &dwOutVersion,
        &msgReply);
    
    if (status == ERROR_SUCCESS && dwOutVersion == 2) {
        // Process the topology information from DC info
        PDRS_TOPOLOGY_INFO pTopology = (PDRS_TOPOLOGY_INFO)LocalAlloc(LPTR, sizeof(DRS_TOPOLOGY_INFO));
        if (pTopology) {
            // Parse the site topology from the DC information
            pTopology->cSites = 0;
            pTopology->cDCs = msgReply.V2.cItems;
            
            // Copy the DC information into our topology structure
            // Note: This would be expanded in a full implementation
            *ppTopologyInfo = pTopology;
        } else {
            status = ERROR_OUTOFMEMORY;
        }
        
        // Free the reply data
        if (msgReply.V2.rItems) {
            kull_m_rpc_ms_drsr_FreeDRS_MSG_DCINFOREPLY_V2(&msgReply);
        }
    }
    
    return status;
}

// Helper function to parse object attributes from a DRS reply
BOOL DRS_ParseObjectAttributes(
    ENTINF* pEntInf, 
    LPWSTR objectDN, 
    SIZE_T objectDNSize, 
    PBYTE* ppObjectSid, 
    PDWORD pcbObjectSid)
{
    BOOL status = FALSE;
    DWORD i, j;
    
    if (!pEntInf || !objectDN || objectDNSize == 0)
        return FALSE;
    
    // Extract the object's distinguished name
    if (pEntInf->pName && pEntInf->pName->NameLen > 0) {
        wcsncpy_s(objectDN, objectDNSize, pEntInf->pName->StringName, min(pEntInf->pName->NameLen, objectDNSize - 1));
        status = TRUE;
    }
    
    // Process attributes if requested
    if (status && ppObjectSid && pcbObjectSid && pEntInf->AttrBlock.attrCount > 0) {
        *ppObjectSid = NULL;
        *pcbObjectSid = 0;
        
        // Search for objectSid attribute (ATT_OBJECT_SID is typically 0x00000590)
        for (i = 0; i < pEntInf->AttrBlock.attrCount; i++) {
            if (pEntInf->AttrBlock.pAttr[i].attrTyp == ATT_OBJECT_SID) {
                for (j = 0; j < pEntInf->AttrBlock.pAttr[i].AttrVal.valCount; j++) {
                    ATTRVAL* pVal = &pEntInf->AttrBlock.pAttr[i].AttrVal.pAVal[j];
                    if (pVal->pVal && pVal->valLen > 0) {
                        // Allocate and copy the SID
                        *ppObjectSid = (PBYTE)LocalAlloc(LPTR, pVal->valLen);
                        if (*ppObjectSid) {
                            memcpy(*ppObjectSid, pVal->pVal, pVal->valLen);
                            *pcbObjectSid = pVal->valLen;
                        }
                        break;
                    }
                }
                break;
            }
        }
    }
    
    return status;
}

// Function to set custom logging for DRS operations
ULONG DRS_SetOperationLogging(PHANDLE phLogFile, LPWSTR logFilePath, DWORD logLevel)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    
    if (!phLogFile)
        return ERROR_INVALID_PARAMETER;
        
    // Close existing log if any
    if (*phLogFile != NULL && *phLogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(*phLogFile);
        *phLogFile = INVALID_HANDLE_VALUE;
    }
    
    // If no path provided, just disable logging
    if (!logFilePath || !logFilePath[0])
        return ERROR_SUCCESS;
        
    // Create or open log file
    hFile = CreateFile(
        logFilePath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
        
    if (hFile == INVALID_HANDLE_VALUE)
        return GetLastError();
        
    // Write log header with version info
    if (hFile != INVALID_HANDLE_VALUE) {
        WCHAR header[256];
        DWORD written;
        
        StringCbPrintfW(header, sizeof(header), 
            L"DRS Client Log - Started at %s\r\n"
            L"Log Level: %u\r\n"
            L"----------------------------------\r\n",
            L"[timestamp placeholder]", logLevel);
            
        WriteFile(hFile, header, (DWORD)wcslen(header) * sizeof(WCHAR), &written, NULL);
    }
    
    *phLogFile = hFile;
    return ERROR_SUCCESS;
}

// Implementation of DRS_MSG_KCC_EXECUTE_Free for cleanup
void DRS_MSG_KCC_EXECUTE_Free(handle_t _MidlEsHandle, DRS_MSG_KCC_EXECUTE* _pType)
{
    if (!_pType)
        return;
        
    // This is a simple structure with no allocated members, so we don't need
    // to free anything here. This function is included for API completeness.
}

// Define DRS_TOPOLOGY_INFO_Free to clean up topology info
void DRS_TOPOLOGY_INFO_Free(PDRS_TOPOLOGY_INFO pTopology)
{
    if (!pTopology)
        return;
        
    // Free any internal allocations
    if (pTopology->pSiteNames) {
        for (DWORD i = 0; i < pTopology->cSites; i++) {
            if (pTopology->pSiteNames[i])
                LocalFree(pTopology->pSiteNames[i]);
        }
        LocalFree(pTopology->pSiteNames);
    }
    
    // Free the main structure
    LocalFree(pTopology);
}

// Helper function to properly clean up DRS resources
ULONG DRS_Unbind(DRS_HANDLE *phDrs)
{
    if (!phDrs || !*phDrs)
        return ERROR_INVALID_PARAMETER;
        
    return IDL_DRSUnbind(phDrs);
}

// Special DRS function to retrieve domain passwords (limited use)
// WARNING: This is a highly privileged operation and should be used with caution
ULONG DRS_GetAccountPasswords(DRS_HANDLE hDrs, LPWSTR userName, PBYTE* ppResults, PDWORD pcbResults)
{
    // This is a placeholder for a sensitive function that could be implemented
    // It would allow extraction of password data if the caller has sufficient privileges
    
    // Implementation would involve:
    // 1. Creating a GetNCChanges request for the user's object
    // 2. Setting the proper flags to retrieve confidential attributes
    // 3. Processing the encrypted attributes from the response
    
    // For security reasons, this remains unimplemented
    if (!hDrs || !userName || !ppResults || !pcbResults)
        return ERROR_INVALID_PARAMETER;
        
    *ppResults = NULL;
    *pcbResults = 0;
    
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void DRS_MSG_GETCHGREPLY_V6_Free(handle_t _MidlEsHandle, DRS_MSG_GETCHGREPLY_V6 * _pType)
{
	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_TypeFormatString.Format[560], _pType);
}

void DRS_MSG_CRACKREPLY_V1_Free(handle_t _MidlEsHandle, DRS_MSG_CRACKREPLY_V1 * _pType)
{
	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO ) &__MIDL_TypePicklingInfo, &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_TypeFormatString.Format[682], _pType);
}

void DRS_MSG_DCINFOREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_DCINFOREPLY_V2 * _pType)
{
	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO  )&__MIDL_TypePicklingInfo, &drsuapi_c_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_TypeFormatString.Format[792], _pType);
}

void DRS_MSG_ADDENTRYREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_ADDENTRYREPLY_V2 * _pType)
{
	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &drsuapi_c_StubDesc, (PFORMAT_STRING ) &ms2Ddrsr__MIDL_TypeFormatString.Format[858], _pType);
}

static const ms2Ddrsr_MIDL_PROC_FORMAT_STRING ms2Ddrsr__MIDL_ProcFormatString = {0, {
	0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x32, 0x00, 0x00, 0x00, 0x44, 0x00, 0x40, 0x00, 0x47, 0x05, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
	0x08, 0x00, 0x78, 0x03, 0x0b, 0x00, 0x10, 0x00, 0x7c, 0x03, 0x13, 0x20, 0x18, 0x00, 0xa4, 0x03, 0x10, 0x01, 0x20, 0x00, 0xac, 0x03, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x30, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x40, 0x00, 0x44, 0x02, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00,
	0xb4, 0x03, 0x70, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0xc0, 0x03, 0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0x01,
	0x20, 0x00, 0x74, 0x04, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x20, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x08, 0x00, 0x46, 0x04,
	0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x8e, 0x04, 0x70, 0x00, 0x18, 0x00,
	0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x20, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x08, 0x00, 0x46, 0x04, 0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0xc2, 0x04, 0x70, 0x00, 0x18, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x20, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x08, 0x00, 0x46, 0x04, 0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03,
	0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x04, 0x05, 0x70, 0x00, 0x18, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00,
	0x2c, 0x00, 0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00,
	0x34, 0x05, 0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0x81, 0x20, 0x00, 0x8a, 0x05, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x08, 0x00, 0x32, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00,
	0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0xdc, 0x05,
	0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0x21, 0x20, 0x00, 0x2e, 0x06, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x08, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x24, 0x00,
	0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x48, 0x06, 0x50, 0x21,
	0x18, 0x00, 0x08, 0x00, 0x13, 0x41, 0x20, 0x00, 0x72, 0x06, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x30, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00,
	0x2c, 0x00, 0x24, 0x00, 0x47, 0x06, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x48, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x10, 0x00,
	0x8c, 0x06, 0x50, 0x21, 0x18, 0x00, 0x08, 0x00, 0x13, 0xa1, 0x20, 0x00, 0xc6, 0x06, 0x70, 0x00, 0x28, 0x00, 0x08, 0x00, 0x00,
}};
#endif

void SRV_OpnumNotImplemented(handle_t IDL_handle)
{
}

ULONG SRV_IDL_DRSReplicaAddNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd)
{
	return STATUS_NOT_IMPLEMENTED;
}

ULONG SRV_IDL_DRSReplicaDelNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel)
{
	return STATUS_NOT_IMPLEMENTED;
}

ULONG SRV_IDL_DRSCrackNamesNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut)
{
	return STATUS_NOT_IMPLEMENTED;
}

ULONG SRV_IDL_DRSDomainControllerInfoNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut)
{
	return STATUS_NOT_IMPLEMENTED;
}

ULONG SRV_IDL_DRSAddEntryNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut)
{
	return STATUS_NOT_IMPLEMENTED;
}