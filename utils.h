#pragma once

#include <Windows.h>

using namespace std;

DWORD CreatePrivProc(PHANDLE hPrivProc, LPWSTR commandLine);
BOOL CloneHandle(DWORD ownerPid, HANDLE handle, PHANDLE clonedHandle);
DWORD GetTargetIntegrityLevel(HANDLE hProc);
DWORD GetTargetIntegrityLevel(DWORD pid);
wstring GetProcName(DWORD pid);