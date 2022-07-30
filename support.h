#pragma once
#include <Windows.h>


#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004;

// handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeNumber;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[10240000];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


//#define SE_DEBUG_PRIVILEGE 0x13
//#define OB_TYPE_INDEX_TYPE              1 // [ObjT] "Type"
//#define OB_TYPE_INDEX_DIRECTORY         2 // [Dire] "Directory"
//#define OB_TYPE_INDEX_SYMBOLIC_LINK     3 // [Symb] "SymbolicLink"
#define OB_TYPE_INDEX_TOKEN             5 // [Toke] "Token"
#define OB_TYPE_INDEX_PROCESS           7 // [Proc] "Process"
#define OB_TYPE_INDEX_THREAD            8 // [Thre] "Thread"
//#define OB_TYPE_INDEX_JOB               7 // [Job ] "Job"
//#define OB_TYPE_INDEX_EVENT             8 // [Even] "Event"
//#define OB_TYPE_INDEX_EVENT_PAIR        9 // [Even] "EventPair"
//#define OB_TYPE_INDEX_MUTANT           10 // [Muta] "Mutant"
//#define OB_TYPE_INDEX_CALLBACK         11 // [Call] "Callback"
//#define OB_TYPE_INDEX_SEMAPHORE        12 // [Sema] "Semaphore"
//#define OB_TYPE_INDEX_TIMER            13 // [Time] "Timer"
//#define OB_TYPE_INDEX_PROFILE          14 // [Prof] "Profile"
//#define OB_TYPE_INDEX_WINDOW_STATION   15 // [Wind] "WindowStation"
//#define OB_TYPE_INDEX_DESKTOP          16 // [Desk] "Desktop"
//#define OB_TYPE_INDEX_SECTION          17 // [Sect] "Section"
//#define OB_TYPE_INDEX_KEY              18 // [Key ] "Key"
//#define OB_TYPE_INDEX_PORT             19 // [Port] "Port"
//#define OB_TYPE_INDEX_WAITABLE_PORT    20 // [Wait] "WaitablePort"
//#define OB_TYPE_INDEX_ADAPTER          21 // [Adap] "Adapter"
//#define OB_TYPE_INDEX_CONTROLLER       22 // [Cont] "Controller"
//#define OB_TYPE_INDEX_DEVICE           23 // [Devi] "Device"
//#define OB_TYPE_INDEX_DRIVER           24 // [Driv] "Driver"
//#define OB_TYPE_INDEX_IO_COMPLETION    25 // [IoCo] "IoCompletion"
#define OB_TYPE_INDEX_FILE             0x37 // [File] "File"
//#define OB_TYPE_INDEX_WMI_GUID         27 // [WmiG] "WmiGuid" 