/*
Copyright (c) 2016 Kasper F. Brandt

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 1
#include <windows.h>
#include <Psapi.h>
#include <winternl.h>
#include <Dbgeng.h>

#include "soswow64.h"
#include "mhook.h"

typedef HRESULT(WINAPI *_GetExecutingProcessorType)(
	IDebugControl4 *dbgCtrl,
	_Out_ PULONG Type);

static _GetExecutingProcessorType RealGetExecutingProcessorType;
static BOOL getExecutingProcessorTypeHooked = FALSE;
static PVOID patchedAddr = NULL;
static WORD orgPatchedValue;

void * _ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)

typedef struct _LANGANDCODEPAGE {
  WORD wLanguage;
  WORD wCodePage;
} LANGANDCODEPAGE, *PLANGANDCODEPAGE;

static BOOL CheckIsSoSByOrgFilename(void* caller)
{
	HMODULE module;
	if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)caller, &module))
		return FALSE;
	HRSRC resInfo = FindResource(module, MAKEINTRESOURCE(VS_VERSION_INFO), RT_VERSION);
	if (!resInfo)
		return FALSE;
	DWORD resSize = SizeofResource(module, resInfo);
	if (!resSize)
		return FALSE;
	HGLOBAL resData = LoadResource(module, resInfo);
	if (!resData)
		return FALSE;
	void* resPtr = LockResource(resData);
	if (!resPtr)
		return FALSE;
	void* resCopy = malloc(resSize);
	memcpy(resCopy, resPtr, resSize);
	PLANGANDCODEPAGE translation;
	DWORD cbTranslate;
	BOOL ret = FALSE;
	if (!VerQueryValue(resCopy, L"\\VarFileInfo\\Translation", &translation, &cbTranslate))
	{
		goto cleanup;
	}
	wchar_t subBlock[42];
	for (DWORD i = 0; i < cbTranslate / sizeof(LANGANDCODEPAGE); i++)
	{
		wsprintf(subBlock, L"\\StringFileInfo\\%04x%04x\\OriginalFileName",
			translation[i].wLanguage,
			translation[i].wCodePage);
		LPWSTR orgFileName;
		DWORD cbOrgFileName;
		if (!VerQueryValue(resCopy, subBlock, &orgFileName, &cbOrgFileName) || !cbOrgFileName)
			continue;
		if (_wcsicmp(orgFileName, L"sos.dll") == 0)
		{
			ret = TRUE;
			break;
		}
	}
cleanup:
	free(resCopy);
	return ret;
}

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
	{
		free(imageName);
		return RealGetExecutingProcessorType(dbgCtrl, Type);
	}

	LPWSTR filenamePart = wcsrchr(imageName, L'\\');
	BOOL isSoS = filenamePart && _wcsicmp(filenamePart + 1, L"sos.dll") == 0;
	free(imageName);
	if (!isSoS)
	{
		isSoS = CheckIsSoSByOrgFilename(caller);
	}
	if (isSoS)
		return dbgCtrl->lpVtbl->GetEffectiveProcessorType(dbgCtrl, Type);
	else
		return RealGetExecutingProcessorType(dbgCtrl, Type);
}
// DbgEng.lib fails to export this
static const GUID IID_IDebugControl4 = 
	{ 0x94e60ce9, 0x9b41, 0x4b19, { 0x9f, 0xc0, 0x6d, 0x9e, 0xb3, 0x52, 0x72, 0xb3 } };

static BOOL PatchWithWord(PVOID addr, WORD value, PWORD oldValue)
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	UINT_PTR addrPage = ((UINT_PTR)addr / sysinfo.dwPageSize) * sysinfo.dwPageSize;
	DWORD oldProtect, dummy;
	if (!VirtualProtect((PVOID)addrPage, sysinfo.dwPageSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		return FALSE;
	*oldValue = *(PWORD)addr;
	*(PWORD)addr = value;
	VirtualProtect((PVOID)addrPage, sysinfo.dwPageSize, oldProtect, &dummy);
	return TRUE;
}

// Debugging tools for Windows 10
static const char dbgeng_sig3[17] = { 0x8B, 0x47, 0x08, 0x83, 0xC4, 0x0C, 0x81, 0xB8, 0xC0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x00, 0x00, 0x77 };
// Debugging tools for Windows 8.0, 8.1
static const char dbgeng_sig1[17] = { 0x8B, 0x46, 0x08, 0x83, 0xC4, 0x0C, 0x81, 0xB8, 0xA8, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x77 };
// Debugging tools for Windows 7.0
static const char dbgeng_sig2[20] = { 0x83, 0xC4, 0x0C, 0x8B, 0x55, 0xF8, 0x8B, 0x42, 0x10, 0x81, 0xB8, 0xA0, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x77 };
// Debugging tools for Windows Vista
static const char dbgeng_sig4[17] = { 0x8B, 0x45, 0xFC, 0x8B, 0x48, 0x08, 0x81, 0xB9, 0xA0, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x77 };

#define CHECK_AND_PATCH(n) \
	if (*search == sig##n##start && memcmp(search, dbgeng_sig##n, sizeof(dbgeng_sig##n)) == 0) \
	{ \
		PVOID addrToPatch = (PBYTE)search + sizeof(dbgeng_sig##n) - 1; \
		if (PatchWithWord(addrToPatch, 0x9090, &orgPatchedValue)) \
		{ \
			patchedAddr = addrToPatch; \
			return TRUE; \
		} \
		return FALSE; \
	}

static BOOL PatchDbgEng(PVOID textStart, size_t textLen)
{	
	DWORD sig1start = *(DWORD*)dbgeng_sig1;
	DWORD sig2start = *(DWORD*)dbgeng_sig2;
	DWORD sig3start = *(DWORD*)dbgeng_sig3;
	DWORD sig4start = *(DWORD*)dbgeng_sig4;
	DWORD* end = (DWORD*)((PBYTE)textStart + textLen - sizeof(dbgeng_sig1));
	for (DWORD* search = (DWORD*)textStart; search <= end; search = (DWORD*)((PBYTE)search + 1))
	{
		CHECK_AND_PATCH(1);
		CHECK_AND_PATCH(2);
		CHECK_AND_PATCH(3);
		CHECK_AND_PATCH(4);
	}
	return FALSE;
}

#undef CHECK_AND_PATCH

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
		getExecutingProcessorTypeHooked = TRUE;
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
		{
			dbgEngPatched = PatchDbgEng(pbDbgeng + sectionHdrs[i].VirtualAddress, sectionHdrs[i].SizeOfRawData);
			break;
		}
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
	if (patchedAddr)
	{
		PatchWithWord(patchedAddr, orgPatchedValue, &orgPatchedValue);
		patchedAddr = NULL;
	}
}

