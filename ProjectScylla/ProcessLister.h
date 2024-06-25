#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <psapi.h>
#include "DeviceNameResolver.h"
#include "WinApi/ntos.h"

class Process {
public:
	std::uint32_t PID;
	std::uint32_t uSessionId;
	std::uintptr_t uImageBase;
	std::uintptr_t uPebAddress;
	//std::uint32_t uEntryPoint; //RVA without imagebase
	std::uint32_t uImageSize;
	wchar_t pFileName[ MAX_PATH ];
	wchar_t pModulePath[ MAX_PATH ];

	Process( )
	{
		PID = 0;
	}
};

enum ProcessType {
	PROCESS_UNKNOWN,
	PROCESS_MISSING_RIGHTS,
	PROCESS_32,
	PROCESS_64
};

class ProcessLister {
public:

	ProcessLister( )
	{
		pDeviceNameResolver = new DeviceNameResolver( );
	}
	~ProcessLister( )
	{
		delete pDeviceNameResolver;
	}

	std::vector<Process>& getProcessList( );
	static bool isWindows64( );
	static std::uint32_t setDebugPrivileges( );
	std::vector<Process>& getProcessListSnapshotNative( );
	static ProcessType checkIsProcess64( HANDLE hProcess );
private:
	std::vector<Process> vProcessList;

	DeviceNameResolver* pDeviceNameResolver;


	bool getAbsoluteFilePath( HANDLE hProcess, Process* pProcess );

	void handleProcessInformationAndAddToList( PSYSTEM_PROCESSES_INFORMATION pProcess );
	void getProcessImageInformation( HANDLE hProcess, Process* pProcess );
	std::uintptr_t getPebAddressFromProcess( HANDLE hProcess );
};