#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define PSAPI_VERSION 1
// Windows Header Files:
#include <windows.h>
#include <Psapi.h>
#include <winternl.h>
#include <Dbgeng.h>

#include "soswow64.h"
#include "mhook.h"
//#include "cDbgControl.h"

/*typedef 
NTSTATUS (NTAPI *_LdrLoadDll)(
  IN PWCHAR               PathToFile OPTIONAL,
  IN ULONG                Flags OPTIONAL,
  IN PUNICODE_STRING      ModuleFileName,
  OUT PHANDLE             ModuleHandle);

static _LdrLoadDll RealLdrLoadDll;
static bool ldrLoadDllHooked;*/

typedef HRESULT(WINAPI *_GetExecutingProcessorType)(
	IDebugControl4 *dbgCtrl,
	_Out_ PULONG Type);

static _GetExecutingProcessorType RealGetExecutingProcessorType;
static BOOL getExecutingProcessorTypeHooked;

void * _ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)

static HRESULT WINAPI HookGetExecutingProcessorType(
	IDebugControl4* dbgCtrl,
	_Out_ PULONG Type)
{
	void* caller = _ReturnAddress();
	MEMORY_BASIC_INFORMATION meminfo;
	if (!VirtualQuery(caller, &meminfo, sizeof(meminfo)))
		return RealGetExecutingProcessorType(dbgCtrl, Type);
	if (meminfo.Type != MEM_IMAGE)
		return RealGetExecutingProcessorType(dbgCtrl, Type);

	LPWSTR imageName = (LPWSTR)malloc(32768);
	if (!GetMappedFileName(GetCurrentProcess(), caller, imageName, 32768))
		return RealGetExecutingProcessorType(dbgCtrl, Type);

	LPWSTR filenamePart = wcsrchr(imageName, L'\\');
	if (!filenamePart || (_wcsicmp(filenamePart+1, L"sos.dll") != 0))
	{
		free(imageName);
		return RealGetExecutingProcessorType(dbgCtrl, Type);
	}
	free(imageName);
	return dbgCtrl->lpVtbl->GetEffectiveProcessorType(dbgCtrl, Type);
}
// DbgEng.lib fails to export this
static const GUID IID_IDebugControl4 = 
	{ 0x94e60ce9, 0x9b41, 0x4b19, { 0x9f, 0xc0, 0x6d, 0x9e, 0xb3, 0x52, 0x72, 0xb3 } };

static BOOL PatchWith2Nops(PVOID addr)
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	UINT_PTR addrPage = ((UINT_PTR)addr / sysinfo.dwPageSize) * sysinfo.dwPageSize;
	DWORD oldProtect, dummy;
	if (!VirtualProtect((PVOID)addrPage, sysinfo.dwPageSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		return FALSE;
	*(WORD*)addr = 0x9090;
	VirtualProtect((PVOID)addrPage, sysinfo.dwPageSize, oldProtect, &dummy);
	return TRUE;
}

// Debuging tools for Windows 10
static const char dbgeng_sig3[17] = { 0x8B, 0x47, 0x08, 0x83, 0xC4, 0x0C, 0x81, 0xB8, 0xC0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x00, 0x00, 0x77 };
// Debugging tools for Windows 8.0, 8.1
static const char dbgeng_sig1[17] = { 0x8B, 0x46, 0x08, 0x83, 0xC4, 0x0C, 0x81, 0xB8, 0xA8, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x77 };
// Debugging tools for Windows 7.0
static const char dbgeng_sig2[20] = { 0x83, 0xC4, 0x0C, 0x8B, 0x55, 0xF8, 0x8B, 0x42, 0x10, 0x81, 0xB8, 0xA0, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x77 };
// Debugging tools for Windows Vista
static const char dbgeng_sig4[18] = { 0x8B, 0x45, 0xFC, 0x8B, 0x48, 0x08, 0x81, 0xB9, 0xA0, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x77, 0x1F };

static BOOL PatchDbgEng(PVOID textStart, size_t textLen)
{	
	DWORD sig1start = *(DWORD*)dbgeng_sig1;
	DWORD sig2start = *(DWORD*)dbgeng_sig2;
	DWORD sig3start = *(DWORD*)dbgeng_sig3;
	DWORD sig4start = *(DWORD*)dbgeng_sig4;
	DWORD* end = (DWORD*)((PBYTE)textStart + textLen - sizeof(dbgeng_sig1));
	for (DWORD* search = (DWORD*)textStart; search <= end; search = (DWORD*)((PBYTE)search + 1))
	{
		if (*search == sig1start && memcmp(search, dbgeng_sig1, sizeof(dbgeng_sig1)) == 0)
		{
			return PatchWith2Nops((PBYTE)search + sizeof(dbgeng_sig1) - 1);
		}
		if (*search == sig2start && memcmp(search, dbgeng_sig2, sizeof(dbgeng_sig2)) == 0)
		{
			return PatchWith2Nops((PBYTE)search + sizeof(dbgeng_sig2) - 1);
		}
		if (*search == sig3start && memcmp(search, dbgeng_sig3, sizeof(dbgeng_sig3)) == 0)
		{
			return PatchWith2Nops((PBYTE)search + sizeof(dbgeng_sig3) - 1);
		}
		if (*search == sig4start && memcmp(search, dbgeng_sig4, sizeof(dbgeng_sig4)) == 0)
		{
			return PatchWith2Nops((PBYTE)search + sizeof(dbgeng_sig4) - 1);
		}
	}
	return FALSE;
}

SOSWOW64_API(HRESULT) DebugExtensionInitialize(
	_Out_ PULONG Version,
	_Out_ PULONG Flags
	)
{
	*Version = DEBUG_EXTENSION_VERSION(1, 0);
	*Flags = 0;
	
	HRESULT err = S_OK;
	IDebugControl4* dbgctrl; 
	if (!SUCCEEDED(err = DebugCreate(&IID_IDebugControl4, (PVOID*)&dbgctrl)))
		return err;
	
	RealGetExecutingProcessorType = dbgctrl->lpVtbl->GetExecutingProcessorType;
	if (!Mhook_SetHook((PVOID*)&RealGetExecutingProcessorType, (PVOID)HookGetExecutingProcessorType))
	{
		dbgctrl->lpVtbl->OutputWide(dbgctrl, DEBUG_OUTPUT_ERROR, L"Failed hooking IDebugControl::GetExecutingProcessorType.\n");
		err = E_FAIL;
		goto cleanup;
	}
	else
	{
		dbgctrl->lpVtbl->OutputWide(dbgctrl, DEBUG_OUTPUT_NORMAL, L"Successfully hooked IDebugControl::GetExecutingProcessorType.\n");
	}

	PIMAGE_DOS_HEADER dbgeng = (PIMAGE_DOS_HEADER)(GetModuleHandle(L"dbgeng.dll"));
	PBYTE pbDbgeng = (PBYTE)dbgeng;
	PIMAGE_NT_HEADERS32 peHeader = (PIMAGE_NT_HEADERS32)(pbDbgeng + dbgeng->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHdrs = (PIMAGE_SECTION_HEADER)((PBYTE)peHeader + sizeof(IMAGE_NT_HEADERS32));
	BOOL dbgEngPatched = FALSE;
	for (int i = 0; i < peHeader->FileHeader.NumberOfSections; i++)
	{
		if (strcmp(sectionHdrs[i].Name, ".text") == 0)
			dbgEngPatched = PatchDbgEng(pbDbgeng + sectionHdrs[i].VirtualAddress, sectionHdrs[i].SizeOfRawData);
		break;
	}
	if (dbgEngPatched)
		dbgctrl->lpVtbl->OutputWide(dbgctrl, DEBUG_OUTPUT_ERROR, L"Successfully patched DbgEng!X86MachineInfo::ConvertCanonContextToTarget.\n");
	else
		dbgctrl->lpVtbl->OutputWide(dbgctrl, DEBUG_OUTPUT_ERROR, L"Failed patching DbgEng!X86MachineInfo::ConvertCanonContextToTarget, stack related commands may not work correctly.\n");

cleanup:
	dbgctrl->lpVtbl->Release(dbgctrl);
	return err;
}

SOSWOW64_API(void) DebugExtensionUninitialize(void)
{
	if (getExecutingProcessorTypeHooked)
	{
		Mhook_Unhook((PVOID*)&RealGetExecutingProcessorType);
		getExecutingProcessorTypeHooked = FALSE;
	}
}

