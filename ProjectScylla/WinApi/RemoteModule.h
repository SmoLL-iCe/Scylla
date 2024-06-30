#pragma once
#include <Windows.h>
#include <string>

namespace RemoteModule { 

	void* GetProcessPeb( HANDLE hProcess, bool bIs64bit );

	HMODULE GetHandleW( HANDLE hProcess, const wchar_t* pModuleName, ULONG* pOutModuleSize,
		bool bIs64bit, bool bCaseSensitive = false );

	std::wstring GetFullModulePathFromBase( HANDLE hProcess, HMODULE hModule, bool bIs64bit );
}
