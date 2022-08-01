#include <windows.h>

#include <map>
#include <string>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

DWORD CreatePrivProc(PHANDLE hPrivProc, LPWSTR commandLine) {
	STARTUPINFOEX sinfo = { sizeof(sinfo) };
	PROCESS_INFORMATION pinfo;
	LPPROC_THREAD_ATTRIBUTE_LIST ptList = NULL;
	SIZE_T bytes = 0;

	sinfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
	InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
	if (bytes == 0)
		return FALSE;
	ptList = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LPTR, bytes);
	if (ptList == NULL)
		return false;
	InitializeProcThreadAttributeList(ptList, 1, 0, &bytes);

	UpdateProcThreadAttribute(ptList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, hPrivProc, sizeof(HANDLE), NULL, NULL);
	sinfo.lpAttributeList = ptList;

	if (CreateProcess(NULL, commandLine,
		NULL, NULL, TRUE,
		EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
		&sinfo.StartupInfo, &pinfo)) {
		return pinfo.dwProcessId;
	}
	else {
		return 0;
	}
}

BOOL CloneHandle(DWORD ownerPid, HANDLE handle, PHANDLE clonedHandle) {
	HANDLE elevatedToken = NULL;
	HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
	if (hOwner == NULL)
		return FALSE;
	bool result = DuplicateHandle(
		hOwner,
		handle,
		GetCurrentProcess(),
		clonedHandle,
		NULL,
		false,
		DUPLICATE_SAME_ACCESS
	);
	CloseHandle(hOwner);
	return result;
}

DWORD GetTargetIntegrityLevel(HANDLE hProc) {
	HANDLE hToken;
	if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProc);
		return 0;
	}
	PTOKEN_MANDATORY_LABEL tokenInformation;
	DWORD returnLength;
	DWORD integrityLevel;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLength);
	if (returnLength <= 0) {
		CloseHandle(hToken);
		CloseHandle(hProc);
		return 0;
	}
	tokenInformation = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, returnLength);
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, tokenInformation, returnLength, &returnLength)) {
		LocalFree(tokenInformation);
		CloseHandle(hToken);
		CloseHandle(hProc);
		return 0;
	}
	integrityLevel = *GetSidSubAuthority(tokenInformation->Label.Sid,
		(DWORD)(UCHAR)(*GetSidSubAuthorityCount(tokenInformation->Label.Sid) - 1));
	LocalFree(tokenInformation);
	CloseHandle(hToken);
	CloseHandle(hProc);
	return integrityLevel;
}

DWORD GetTargetIntegrityLevel(DWORD pid) {
	HANDLE hProc;
	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProc == NULL)
		return 0;
	return GetTargetIntegrityLevel(hProc);
}

wstring GetProcName(DWORD pid)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		return wstring();
	}

	for (BOOL bok = Process32First(processesSnapshot, &processInfo); bok; bok = Process32Next(processesSnapshot, &processInfo))
	{
		if (pid == processInfo.th32ProcessID)
		{
			CloseHandle(processesSnapshot);
			return processInfo.szExeFile;
		}

	}
	CloseHandle(processesSnapshot);
	return wstring();
}