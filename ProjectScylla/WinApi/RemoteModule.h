#pragma once
#include <Windows.h>
#include <string>
#include <functional>

struct sPebModuleInfo
{
	PVOID DllBase = nullptr;
	PVOID EntryPoint = nullptr;
	ULONG SizeOfImage = 0;
	wchar_t FullDllName[ MAX_PATH ];
	wchar_t BaseDllName[ MAX_PATH ];
};

namespace RemoteModule { 

	void* GetProcessPeb( HANDLE hProcess, bool bIs64bit );

	HMODULE GetHandleW( HANDLE hProcess, const wchar_t* pModuleName, ULONG* pOutModuleSize,
		bool bIs64bit, bool bCaseSensitive = false );

	std::size_t GetSizeOfModuleFromPage( HANDLE hProcess, PVOID pModule );

	std::wstring GetModulePathFromPage( HANDLE hProcess, PVOID pModule );

	std::wstring GetFullModulePathFromBase( HANDLE hProcess, HMODULE hModule, bool bIs64bit );

	void EnumModulesInfo( HANDLE hProcess, bool bIs64bit, std::function<bool( sPebModuleInfo* )> fnCallback );
}
