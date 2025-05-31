/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../../modules/kull_m_process.h"
#include "../../modules/kull_m_memory.h"
#include <wbemidl.h>
#include <virtdisk.h>
#include <initguid.h>
#include <vhdsvc.h>

// HyperV Data Structures
typedef enum _HYPERV_VM_STATE {
    HYPERV_STATE_UNKNOWN = 0,
    HYPERV_STATE_OTHER = 1,
    HYPERV_STATE_RUNNING = 2,
    HYPERV_STATE_OFF = 3,
    HYPERV_STATE_STOPPING = 4,
    HYPERV_STATE_SAVED = 6,
    HYPERV_STATE_PAUSED = 9,
    HYPERV_STATE_STARTING = 10,
    HYPERV_STATE_RESET = 11,
    HYPERV_STATE_SAVING = 32773,
    HYPERV_STATE_PAUSING = 32776,
    HYPERV_STATE_RESUMING = 32777,
    HYPERV_STATE_UNKNOWN_32769 = 32769,
    HYPERV_STATE_UNKNOWN_32770 = 32770,
    HYPERV_STATE_UNKNOWN_32771 = 32771,
    HYPERV_STATE_UNKNOWN_32772 = 32772
} HYPERV_VM_STATE;

typedef struct _HYPERV_VM_INFO {
    LPWSTR vmName;
    LPWSTR vmId; 
    HYPERV_VM_STATE state;
    LPWSTR configurationLocation;
    LONGLONG memorySize;
    LPWSTR version;
    LPWSTR notes;
    HANDLE hProcess;  // For memory access
} HYPERV_VM_INFO, *PHYPERV_VM_INFO;

typedef struct _HYPERV_CONFIG {
    BOOL useRemoteWmi;
    LPWSTR remoteMachine;
    LPWSTR remoteUser;
    LPWSTR remotePassword;
    BOOL useVerbose;
    BOOL ignoreOfflineVMs;
} HYPERV_CONFIG, *PHYPERV_CONFIG;

// HyperV module declaration
const KUHL_M kuhl_m_hyperv;

// Main module functions
NTSTATUS kuhl_m_hyperv_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_hyperv_memory(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_hyperv_snapshot(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_hyperv_vhdmount(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_hyperv_credential(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_hyperv_network(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_hyperv_create(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_hyperv_control(int argc, wchar_t * argv[]);

// Helper functions
BOOL hyperv_getVMList(PHYPERV_CONFIG pConfig, PHYPERV_VM_INFO* ppVMs, DWORD* count);
BOOL hyperv_openVMMemory(PHYPERV_VM_INFO pVM);
BOOL hyperv_readVMMemory(PHYPERV_VM_INFO pVM, PVOID baseAddress, PVOID buffer, SIZE_T size);
BOOL hyperv_writeVMMemory(PHYPERV_VM_INFO pVM, PVOID baseAddress, PVOID buffer, SIZE_T size);
void hyperv_freeVMInfo(PHYPERV_VM_INFO pVMs, DWORD count);
BOOL hyperv_connectToRemote(PHYPERV_CONFIG pConfig, IWbemServices** ppWbemServices);
HYPERV_VM_STATE hyperv_getStateFromInt(DWORD state);
LPWSTR hyperv_getStateString(HYPERV_VM_STATE state);
BOOL hyperv_mountVHD(LPCWSTR vhdPath, WCHAR* mountPath, size_t mountPathSize);
BOOL hyperv_unmountVHD(LPCWSTR vhdPath);
BOOL hyperv_createSnapshot(PHYPERV_VM_INFO pVM, LPWSTR snapshotName);
BOOL hyperv_applySnapshot(PHYPERV_VM_INFO pVM, LPWSTR snapshotId);

// Advanced VM memory functions
DWORD hyperv_findProcessByName(PHYPERV_VM_INFO pVM, LPCWSTR processName);
BOOL hyperv_dumpProcess(PHYPERV_VM_INFO pVM, DWORD pid, LPCWSTR dumpFile);
BOOL kuhl_m_hyperv_credential_sekurlsa(LPCWSTR dumpFile);
