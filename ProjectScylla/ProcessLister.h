#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include "DeviceNameResolver.h"
#include "WinApi/ntos.h"

enum ProcessType {
	PROCESS_UNKNOWN,
	PROCESS_MISSING_RIGHTS,
	PROCESS_32,
	PROCESS_64
};

class Process {
public:
	std::uint32_t PID;
	std::uint32_t uSessionId;
	std::uintptr_t uImageBase;
	std::uintptr_t uPebAddress;
	std::uint32_t uImageSize;
	wchar_t pFileName[ MAX_PATH ];
	wchar_t pModulePath[ MAX_PATH ];
	ProcessType archType;
	Process( )
	{
		PID = 0;
	}
};

class ProcessLister {
public:
	std::vector<Process>& getProcessList( );
	static bool isWindows64( );
	static std::uint32_t setDebugPrivileges( );
	std::vector<Process>& getProcessListSnapshotNative( );
	static ProcessType checkIsProcess64( HANDLE hProcess );
private:
	std::vector<Process> vProcessList;


	bool getAbsoluteFilePath( HANDLE hProcess, Process* pProcess );

	void handleProcessInformationAndAddToList( PSYSTEM_PROCESSES_INFORMATION pProcess );
	void getProcessImageInformation( HANDLE hProcess, Process* pProcess );
	std::uintptr_t getPebAddressFromProcess( HANDLE hProcess, ProcessType archType );
};