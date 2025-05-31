#pragma once
#include "kull_m_rpc.h"

typedef LONGLONG DSTIME;
typedef LONGLONG USN;
typedef ULONG ATTRTYP;
typedef void *DRS_HANDLE;

typedef struct _NT4SID {
	UCHAR Data[28];
} NT4SID;

typedef struct _DSNAME {
	ULONG structLen;
	ULONG SidLen;
	GUID Guid;
	NT4SID Sid;
	ULONG NameLen;
	WCHAR StringName[ANYSIZE_ARRAY];
} DSNAME;

typedef struct _USN_VECTOR {
	USN usnHighObjUpdate;
	USN usnReserved;
	USN usnHighPropUpdate;
} USN_VECTOR;

typedef struct _UPTODATE_CURSOR_V1 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
} UPTODATE_CURSOR_V1;

typedef struct _UPTODATE_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V1 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V1_EXT;

typedef struct _OID_t {
	unsigned int length;
	BYTE *elements;
} OID_t;

typedef struct _PrefixTableEntry {
	ULONG ndx;
	OID_t prefix;
} PrefixTableEntry;

typedef struct _SCHEMA_PREFIX_TABLE {
	DWORD PrefixCount;
	PrefixTableEntry *pPrefixEntry;
} SCHEMA_PREFIX_TABLE;

typedef struct _PARTIAL_ATTR_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cAttrs;
	ATTRTYP rgPartialAttr[ANYSIZE_ARRAY];
} PARTIAL_ATTR_VECTOR_V1_EXT;

typedef struct _ATTRVAL {
	ULONG valLen;
	UCHAR *pVal;
} ATTRVAL;

typedef struct _ATTRVALBLOCK {
	ULONG valCount;
	ATTRVAL *pAVal;
} ATTRVALBLOCK;

typedef struct _ATTR {
	ATTRTYP attrTyp;
	ATTRVALBLOCK AttrVal;
} ATTR;

typedef struct _ATTRBLOCK {
	ULONG attrCount;
	ATTR *pAttr;
} ATTRBLOCK;

typedef struct _ENTINF {
	DSNAME *pName;
	ULONG ulFlags;
	ATTRBLOCK AttrBlock;
} ENTINF;

typedef struct _PROPERTY_META_DATA_EXT {
	DWORD dwVersion;
	DSTIME timeChanged;
	UUID uuidDsaOriginating;
	USN usnOriginating;
} PROPERTY_META_DATA_EXT;

typedef struct _PROPERTY_META_DATA_EXT_VECTOR {
	DWORD cNumProps;
	PROPERTY_META_DATA_EXT rgMetaData[ANYSIZE_ARRAY];
} PROPERTY_META_DATA_EXT_VECTOR;

typedef struct _REPLENTINFLIST {
	struct _REPLENTINFLIST *pNextEntInf;
	ENTINF Entinf;
	BOOL fIsNCPrefix;
	UUID *pParentGuid;
	PROPERTY_META_DATA_EXT_VECTOR *pMetaDataExt;
} REPLENTINFLIST;

typedef struct _UPTODATE_CURSOR_V2 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
	DSTIME timeLastSyncSuccess;
} UPTODATE_CURSOR_V2;

typedef struct _UPTODATE_VECTOR_V2_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V2 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V2_EXT;

typedef struct _VALUE_META_DATA_EXT_V1 {
	DSTIME timeCreated;
	PROPERTY_META_DATA_EXT MetaData;
} VALUE_META_DATA_EXT_V1;

typedef struct _REPLVALINF_V1 {
	DSNAME *pObject;
	ATTRTYP attrTyp;
	ATTRVAL Aval;
	BOOL fIsPresent;
	VALUE_META_DATA_EXT_V1 MetaData;
} REPLVALINF_V1;

typedef struct _REPLTIMES {
	UCHAR rgTimes[84];
} REPLTIMES;

typedef struct _DS_NAME_RESULT_ITEMW {
	DWORD status;
	WCHAR *pDomain;
	WCHAR *pName;
} DS_NAME_RESULT_ITEMW, *PDS_NAME_RESULT_ITEMW;

typedef struct _DS_NAME_RESULTW {
	DWORD cItems;
	PDS_NAME_RESULT_ITEMW rItems;
} DS_NAME_RESULTW, *PDS_NAME_RESULTW;

typedef struct _DS_DOMAIN_CONTROLLER_INFO_2W {
	WCHAR *NetbiosName;
	WCHAR *DnsHostName;
	WCHAR *SiteName;
	WCHAR *SiteObjectName;
	WCHAR *ComputerObjectName;
	WCHAR *ServerObjectName;
	WCHAR *NtdsDsaObjectName;
	BOOL fIsPdc;
	BOOL fDsEnabled;
	BOOL fIsGc;
	GUID SiteObjectGuid;
	GUID ComputerObjectGuid;
	GUID ServerObjectGuid;
	GUID NtdsDsaObjectGuid;
} DS_DOMAIN_CONTROLLER_INFO_2W;

typedef struct _ENTINFLIST {
	struct _ENTINFLIST *pNextEntInf;
	ENTINF Entinf;
} ENTINFLIST;

typedef struct _DRS_EXTENSIONS {
	DWORD cb;
	BYTE rgb[ANYSIZE_ARRAY];
} DRS_EXTENSIONS;

typedef struct _DRS_MSG_GETCHGREPLY_V6 {
	UUID uuidDsaObjSrc;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	USN_VECTOR usnvecTo;
	UPTODATE_VECTOR_V2_EXT *pUpToDateVecSrc;
	SCHEMA_PREFIX_TABLE PrefixTableSrc;
	ULONG ulExtendedRet;
	ULONG cNumObjects;
	ULONG cNumBytes;
	REPLENTINFLIST *pObjects;
	BOOL fMoreData;
	ULONG cNumNcSizeObjects;
	ULONG cNumNcSizeValues;
	DWORD cNumValues;
	REPLVALINF_V1 *rgValues;
	DWORD dwDRSError;
} DRS_MSG_GETCHGREPLY_V6;

typedef union _DRS_MSG_GETCHGREPLY {
	DRS_MSG_GETCHGREPLY_V6 V6;
} DRS_MSG_GETCHGREPLY;

typedef struct _DRS_MSG_GETCHGREQ_V8 {
	UUID uuidDsaObjDest;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	UPTODATE_VECTOR_V1_EXT *pUpToDateVecDest;
	ULONG ulFlags;
	ULONG cMaxObjects;
	ULONG cMaxBytes;
	ULONG ulExtendedOp;
	ULARGE_INTEGER liFsmoInfo;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetEx;
	SCHEMA_PREFIX_TABLE PrefixTableDest;
} DRS_MSG_GETCHGREQ_V8;

typedef union _DRS_MSG_GETCHGREQ {
	DRS_MSG_GETCHGREQ_V8 V8;
} DRS_MSG_GETCHGREQ;

typedef struct _DRS_MSG_UPDREFS_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaDest;
	UUID uuidDsaObjDest;
	ULONG ulOptions;
} DRS_MSG_UPDREFS_V1;

typedef union _DRS_MSG_UPDREFS {
	DRS_MSG_UPDREFS_V1 V1;
} 	DRS_MSG_UPDREFS;

typedef struct _DRS_MSG_REPADD_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaSrc;
	REPLTIMES rtSchedule;
	ULONG ulOptions;
} DRS_MSG_REPADD_V1;

typedef union _DRS_MSG_REPADD {
	DRS_MSG_REPADD_V1 V1;
} DRS_MSG_REPADD;

typedef struct _DRS_MSG_REPDEL_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaSrc;
	ULONG ulOptions;
} DRS_MSG_REPDEL_V1;

typedef union _DRS_MSG_REPDEL {
	DRS_MSG_REPDEL_V1 V1;
} DRS_MSG_REPDEL;

typedef struct _DRS_MSG_VERIFYREQ_V1 {
	DWORD dwFlags;
	DWORD cNames;
	DSNAME **rpNames;
	ATTRBLOCK RequiredAttrs;
	SCHEMA_PREFIX_TABLE PrefixTable;
} DRS_MSG_VERIFYREQ_V1;

typedef union _DRS_MSG_VERIFYREQ {
	DRS_MSG_VERIFYREQ_V1 V1;
} DRS_MSG_VERIFYREQ;

typedef struct _DRS_MSG_VERIFYREPLY_V1 {
	DWORD error;
	DWORD cNames;
	ENTINF *rpEntInf;
	SCHEMA_PREFIX_TABLE PrefixTable;
} DRS_MSG_VERIFYREPLY_V1;

typedef union _DRS_MSG_VERIFYREPLY {
	DRS_MSG_VERIFYREPLY_V1 V1;
} DRS_MSG_VERIFYREPLY;

typedef struct _DRS_MSG_CRACKREQ_V1 {
	ULONG CodePage;
	ULONG LocaleId;
	DWORD dwFlags;
	DWORD formatOffered;
	DWORD formatDesired;
	DWORD cNames;
	WCHAR **rpNames;
} DRS_MSG_CRACKREQ_V1;

typedef union _DRS_MSG_CRACKREQ {
	DRS_MSG_CRACKREQ_V1 V1;
} DRS_MSG_CRACKREQ;

typedef struct _DRS_MSG_CRACKREPLY_V1 {
	DS_NAME_RESULTW *pResult;
} DRS_MSG_CRACKREPLY_V1;

typedef union _DRS_MSG_CRACKREPLY {
	DRS_MSG_CRACKREPLY_V1 V1;
} DRS_MSG_CRACKREPLY;

typedef struct _DRS_MSG_DCINFOREQ_V1 {
	WCHAR *Domain;
	DWORD InfoLevel;
} DRS_MSG_DCINFOREQ_V1;

typedef union _DRS_MSG_DCINFOREQ {
	DRS_MSG_DCINFOREQ_V1 V1;
} DRS_MSG_DCINFOREQ, *PDRS_MSG_DCINFOREQ;

typedef struct _DRS_MSG_DCINFOREPLY_V2 {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_2W *rItems;
} DRS_MSG_DCINFOREPLY_V2;

typedef union _DRS_MSG_DCINFOREPLY {
	DRS_MSG_DCINFOREPLY_V2 V2;
} DRS_MSG_DCINFOREPLY;

typedef struct _DRS_MSG_ADDENTRYREQ_V2 {
	ENTINFLIST EntInfList;
} DRS_MSG_ADDENTRYREQ_V2;

typedef union _DRS_MSG_ADDENTRYREQ {
	DRS_MSG_ADDENTRYREQ_V2 V2;
} DRS_MSG_ADDENTRYREQ;

typedef struct _ADDENTRY_REPLY_INFO {
	GUID objGuid;
	NT4SID objSid;
} ADDENTRY_REPLY_INFO;

typedef struct _DRS_MSG_ADDENTRYREPLY_V2 {
	DSNAME *pErrorObject;
	DWORD errCode;
	DWORD dsid;
	DWORD extendedErr;
	DWORD extendedData;
	USHORT problem;
	ULONG cObjectsAdded;
	ADDENTRY_REPLY_INFO *infoList;
} DRS_MSG_ADDENTRYREPLY_V2;

typedef union _DRS_MSG_ADDENTRYREPLY {
	DRS_MSG_ADDENTRYREPLY_V2 V2;
} DRS_MSG_ADDENTRYREPLY;

// Structure for KCC execution request messages
typedef struct _DRS_MSG_KCC_EXECUTE {
    DWORD dwTaskID;      // Task identifier for KCC execution
    DWORD dwFlags;       // Control flags for execution
} DRS_MSG_KCC_EXECUTE, *PDRS_MSG_KCC_EXECUTE;

// Structure to hold DC topology information
typedef struct _DRS_TOPOLOGY_INFO {
    DWORD cSites;           // Number of sites in the forest
    DWORD cDCs;             // Number of domain controllers
    LPWSTR* pSiteNames;     // Array of site names
    LPWSTR* pDCNames;       // Array of DC names
    LPWSTR* pDnsNames;      // Array of DNS names for DCs
    DWORD* pdwSiteIds;      // Array of site IDs
} DRS_TOPOLOGY_INFO, *PDRS_TOPOLOGY_INFO;

// Constants for DRS operation logging
#define DRS_LOG_LEVEL_NONE     0
#define DRS_LOG_LEVEL_ERROR    1
#define DRS_LOG_LEVEL_WARNING  2
#define DRS_LOG_LEVEL_INFO     3
#define DRS_LOG_LEVEL_VERBOSE  4
#define DRS_LOG_LEVEL_DEBUG    5

// Constants for replication flags (expanded from Microsoft docs)
#define DRS_ASYNC_OP                   0x00000001
#define DRS_GETCHG_CHECK               0x00000002
#define DRS_UPDATE_NOTIFICATION        0x00000004
#define DRS_ADD_REF                    0x00000008
#define DRS_SYNC_ALL                   0x00000010
#define DRS_DEL_REF                    0x00000020
#define DRS_WRIT_REP                   0x00000040
#define DRS_INIT_SYNC                  0x00000080
#define DRS_PER_SYNC                   0x00000100
#define DRS_MAIL_REP                   0x00000200
#define DRS_ASYNC_REP                  0x00000400
#define DRS_IGNORE_ERROR               0x00000800
#define DRS_CRITICAL_ONLY              0x00001000
#define DRS_GET_ANC                    0x00002000
#define DRS_GET_NC_SIZE                0x00004000
#define DRS_LOCAL_ONLY                 0x00008000
#define DRS_NONGC_RO_REP               0x00010000
#define DRS_SYNC_BYNAME                0x00020000
#define DRS_REF_OK                     0x00040000
#define DRS_FULL_SYNC_NOW              0x00080000
#define DRS_NO_SOURCE                  0x00100000
#define DRS_FULL_SYNC_IN_PROGRESS      0x00200000
#define DRS_FULL_SYNC_PACKET           0x00400000
#define DRS_SYNC_REQUEUE               0x00800000
#define DRS_SYNC_URGENT                0x01000000
#define DRS_REF_GCSPN                  0x02000000
#define DRS_NO_DISCARD                 0x04000000
#define DRS_NEVER_SYNCED               0x08000000
#define DRS_SPECIAL_SECRET_PROCESSING  0x10000000
#define DRS_INIT_SYNC_NOW              0x20000000
#define DRS_PREEMPTED                  0x40000000
#define DRS_SYNC_FORCED                0x80000000

// Common attribute types (expanded)
#define ATT_OBJECT_SID                 0x00000590
#define ATT_ACCOUNT_NAME               0x00000612
#define ATT_SAM_ACCOUNT_NAME           0x00000601
#define ATT_USER_PRINCIPAL_NAME        0x0000059A
#define ATT_OBJECT_CATEGORY            0x0000000C
#define ATT_OBJECT_CLASS               0x0000000D
#define ATT_NT_SECURITY_DESCRIPTOR     0x00000031
#define ATT_UNICODE_PWD                0x0000009E
#define ATT_DBCS_PWD                   0x0000009D
#define ATT_SUPPLEMENTAL_CREDENTIALS   0x000007D1
#define ATT_PRIMARY_GROUP_ID           0x00000592
#define ATT_ACCOUNT_EXPIRES            0x00000579

// Options for Name Formats in CrackNames function
#define DS_UNKNOWN_NAME                0
#define DS_FQDN_1779_NAME              1
#define DS_NT4_ACCOUNT_NAME            2
#define DS_DISPLAY_NAME                3
#define DS_UNIQUE_ID_NAME              6
#define DS_CANONICAL_NAME              7
#define DS_USER_PRINCIPAL_NAME         8
#define DS_CANONICAL_NAME_EX           9
#define DS_SERVICE_PRINCIPAL_NAME      10
#define DS_SID_OR_SID_HISTORY_NAME     11
#define DS_DNS_DOMAIN_NAME             12

extern RPC_IF_HANDLE drsuapi_v4_0_c_ifspec;
extern RPC_IF_HANDLE drsuapi_v4_0_s_ifspec;

ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs);
ULONG IDL_DRSUnbind(DRS_HANDLE *phDrs);
ULONG IDL_DRSReplicaAdd(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd);
ULONG IDL_DRSReplicaDel(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel);
ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut);
ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut);
ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut);
ULONG IDL_DRSAddEntry(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut);

// Additional DRS function for extended operations
ULONG IDL_DRSExecuteKCC(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_KCC_EXECUTE *pmsgIn);

// Additional helper functions for DRS operations
ULONG DRS_GetTopology(DRS_HANDLE hDrs, LPWSTR siteName, PDRS_TOPOLOGY_INFO* ppTopologyInfo);
BOOL DRS_ParseObjectAttributes(ENTINF* pEntInf, LPWSTR objectDN, SIZE_T objectDNSize, PBYTE* ppObjectSid, PDWORD pcbObjectSid);
ULONG DRS_SetOperationLogging(PHANDLE phLogFile, LPWSTR logFilePath, DWORD logLevel);

// Extended function declarations
ULONG DRS_BindWithCredentials(LPWSTR server, LPWSTR domain, LPCWSTR username, LPCWSTR password, DRS_HANDLE *phDrs);
ULONG DRS_BindWithSpn(LPWSTR server, LPWSTR domain, LPWSTR targetSpn, DRS_HANDLE *phDrs);
ULONG DRS_EnumAllObjects(DRS_HANDLE hDrs, LPWSTR namingContext, LPWSTR filter, HANDLE hOutFile, DWORD dwFlags);
ULONG DRS_FindUser(DRS_HANDLE hDrs, LPCWSTR userName, ENTINF** ppEntInf);
ULONG DRS_GetUserAccountControl(DRS_HANDLE hDrs, LPCWSTR userName, PDWORD pdwUAC);
ULONG DRS_ConvertSidToUsername(DRS_HANDLE hDrs, PSID pSid, LPWSTR *ppName);

// Additional helper functions
BOOL DRS_WriteLogEntry(HANDLE hLogFile, DWORD logLevel, LPCWSTR format, ...);
void DRS_FreeEntInf(ENTINF *pEntInf);
BOOL DRS_CompareAttIds(ATTRTYP attId1, ATTRTYP attId2);
BOOL DRS_IsAdminObject(ENTINF *pEntInf);

// Helper functions for DRS operations
ULONG DRS_Bind(LPWSTR server, LPWSTR domain, DRS_HANDLE *phDrs);
BOOL DRS_CheckCapability(DRS_EXTENSIONS *pServerExtensions, DWORD dwCapability);
ULONG DRS_Unbind(DRS_HANDLE *phDrs);
ULONG DRS_GetAccountPasswords(DRS_HANDLE hDrs, LPWSTR userName, PBYTE* ppResults, PDWORD pcbResults);

// Additional cleanup functions
void DRS_MSG_GETCHGREPLY_V6_Free(handle_t _MidlEsHandle, DRS_MSG_GETCHGREPLY_V6 * _pType);
void DRS_MSG_CRACKREPLY_V1_Free(handle_t _MidlEsHandle, DRS_MSG_CRACKREPLY_V1 * _pType);
void DRS_MSG_DCINFOREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_DCINFOREPLY_V2 * _pType);
void DRS_MSG_ADDENTRYREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_ADDENTRYREPLY_V2 * _pType);
void DRS_MSG_KCC_EXECUTE_Free(handle_t _MidlEsHandle, DRS_MSG_KCC_EXECUTE* _pType);
void DRS_TOPOLOGY_INFO_Free(PDRS_TOPOLOGY_INFO pTopology);

// ARM64 Initialization
#if defined(_M_ARM64)
void IDL_DRS_ARM64_Init(void);
#endif

#define kull_m_rpc_ms_drsr_FreeDRS_MSG_GETCHGREPLY_V6(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_GETCHGREPLY_V6_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_CRACKREPLY_V1(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_CRACKREPLY_V1_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_DCINFOREPLY_V2(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_DCINFOREPLY_V2_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_ADDENTRYREPLY_V2(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_ADDENTRYREPLY_V2_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_KCC_EXECUTE(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_KCC_EXECUTE_Free)

void __RPC_USER SRV_DRS_HANDLE_rundown(DRS_HANDLE hDrs);
ULONG SRV_IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs);
ULONG SRV_IDL_DRSUnbind(DRS_HANDLE *phDrs);
ULONG SRV_IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut);
ULONG SRV_IDL_DRSVerifyNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_VERIFYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_VERIFYREPLY *pmsgOut);
ULONG SRV_IDL_DRSUpdateRefs(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_UPDREFS *pmsgUpdRefs);

void SRV_OpnumNotImplemented(handle_t IDL_handle);
ULONG SRV_IDL_DRSReplicaAddNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd);
ULONG SRV_IDL_DRSReplicaDelNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel);
ULONG SRV_IDL_DRSCrackNamesNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut);
ULONG SRV_IDL_DRSDomainControllerInfoNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut);
ULONG SRV_IDL_DRSAddEntryNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut);