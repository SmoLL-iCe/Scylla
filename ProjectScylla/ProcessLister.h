#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <psapi.h>
#include "DeviceNameResolver.h"
#include "WinApi/ntos.h"

class Process {
public:
	DWORD PID;
    DWORD sessionId;
	DWORD_PTR imageBase;
    DWORD_PTR pebAddress;
	//DWORD entryPoint; //RVA without imagebase
	DWORD imageSize;
	WCHAR filename[MAX_PATH];
	WCHAR fullPath[MAX_PATH];

	Process()
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

	ProcessLister()
	{
		deviceNameResolver = new DeviceNameResolver();
	}
	~ProcessLister()
	{
		delete deviceNameResolver;
	}

	std::vector<Process>& getProcessList();
	static bool isWindows64();
	static DWORD setDebugPrivileges();
    std::vector<Process>& getProcessListSnapshotNative();
private:
	std::vector<Process> processList;

	DeviceNameResolver * deviceNameResolver;

	ProcessType checkIsProcess64(HANDLE hProcess);

	bool getAbsoluteFilePath(HANDLE hProcess, Process * process);

    void handleProcessInformationAndAddToList( PSYSTEM_PROCESSES_INFORMATION pProcess );
    void getProcessImageInformation( HANDLE hProcess, Process* process );
    DWORD_PTR getPebAddressFromProcess( HANDLE hProcess );
};