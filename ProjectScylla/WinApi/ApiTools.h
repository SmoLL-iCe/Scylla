#pragma once
#include <Windows.h>
#include <iostream>
#include "ntos.h"

namespace ApiTools
{
	void CloseHandle( HANDLE hObject );
	SIZE_T __stdcall VirtualQuery( LPVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength );
	LPVOID __stdcall VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect );
	BOOL __stdcall VirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
	BOOL __stdcall VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );


	NTSTATUS __stdcall QueryVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength );


	SIZE_T __stdcall VirtualQueryEx( HANDLE hProcess, LPVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength );
	LPVOID __stdcall VirtualAllocEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect );
	BOOL __stdcall VirtualProtectEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
	BOOL __stdcall VirtualFreeEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );

    BOOL __stdcall ReadProcessMemory( HANDLE hProcess, LPVOID lpBaseAddress,
        LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead );

    BOOL __stdcall WriteProcessMemory( HANDLE hProcess, LPVOID lpBaseAddress, 
        LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten );

	HANDLE __stdcall OpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId );

	HANDLE WINAPI CreateRemoteThread( HANDLE hProcess, void*lpStartAddress, LPVOID lpParameter );

	template <typename A = uintptr_t, typename B = uint8_t*>
	inline bool WriteProtect( HANDLE hProcess, A pAddress, void* pVal, size_t szSize )
	{
		DWORD p;

		if ( !ApiTools::VirtualProtectEx( hProcess, (void*)( (size_t)pAddress ), szSize, PAGE_EXECUTE_READWRITE, &p ) )
			return false;

		const auto bRet = ApiTools::WriteProcessMemory( hProcess, (void*)( (size_t)pAddress ), pVal, szSize, nullptr );

		ApiTools::VirtualProtectEx( hProcess, (void*)( (size_t)pAddress ), szSize, p, &p );

		return bRet;
	}

	template <typename A = uintptr_t>
	inline bool ReadData( HANDLE hProcess, A pAddress, void* pVal, size_t szSize )
	{
		return ApiTools::ReadProcessMemory( hProcess, (void*)( (size_t)pAddress ), pVal, szSize, nullptr );
	}
}


