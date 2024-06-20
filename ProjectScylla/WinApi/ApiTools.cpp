#pragma once
#include "ApiTools.h"
#include <fstream>
#include "ntos.h"

SIZE_T __stdcall ApiTools::VirtualQuery( LPVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength )
{
	return ApiTools::VirtualQueryEx( NtCurrentProcess( ), lpAddress, lpBuffer, dwLength );
}

LPVOID __stdcall ApiTools::VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect )
{
	return ApiTools::VirtualAllocEx( NtCurrentProcess( ), lpAddress, dwSize, flAllocationType, flProtect );
}

BOOL __stdcall ApiTools::VirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
	return ApiTools::VirtualProtectEx( NtCurrentProcess( ), lpAddress, dwSize, flNewProtect, lpflOldProtect );
}

BOOL __stdcall ApiTools::VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
	return ApiTools::VirtualFreeEx( NtCurrentProcess( ), lpAddress, dwSize, dwFreeType );
}

HANDLE __stdcall ApiTools::CreateRemoteThread( HANDLE hProcess, void* lpStartAddress, LPVOID lpParameter )
{
	return ::CreateRemoteThread( hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>( lpStartAddress ), lpParameter, 0, nullptr );
}

LPVOID __stdcall ApiTools::VirtualAllocEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect )
{
	PVOID pAddress = lpAddress;

	SIZE_T Size = dwSize;

	const NTSTATUS Status = NtAllocateVirtualMemory( hProcess, &pAddress, 0, &Size, flAllocationType, flProtect );

	return  ( Status == 0 ) ? pAddress : NULL;
}

SIZE_T __stdcall ApiTools::VirtualQueryEx( HANDLE hProcess, LPVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength )
{
	SIZE_T rSize;

	const NTSTATUS Status = ApiTools::QueryVirtualMemory( hProcess, lpAddress, MemoryBasicInformation, lpBuffer, sizeof( MEMORY_BASIC_INFORMATION ), &rSize );
	
	return  ( Status == 0 ) ? rSize : 0;
}

NTSTATUS __stdcall ApiTools::QueryVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength ) {
	return NtQueryVirtualMemory( ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength );
}
BOOL __stdcall ApiTools::VirtualProtectEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
	PVOID pAddress = lpAddress;

	SIZE_T Size = dwSize;

	const NTSTATUS Status = NtProtectVirtualMemory( hProcess, &pAddress, &Size, flNewProtect, lpflOldProtect )
		;
	return  ( Status == 0 );
}

BOOL __stdcall ApiTools::VirtualFreeEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
	PVOID pAddress = lpAddress;

	SIZE_T Size = dwSize;

	const NTSTATUS Status = NtFreeVirtualMemory( hProcess, &pAddress, &Size, dwFreeType );

	return  ( Status == 0 );
}

BOOL __stdcall ApiTools::ReadProcessMemory( HANDLE hProcess, LPVOID lpBaseAddress,
	LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead ) {

	return NtReadVirtualMemory( hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead ) == 0;
}

BOOL __stdcall ApiTools::WriteProcessMemory( HANDLE hProcess, LPVOID lpBaseAddress,
	LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten ) {
	return NtWriteVirtualMemory( hProcess, lpBaseAddress, (LPVOID)lpBuffer, nSize, lpNumberOfBytesWritten ) == 0;
}

HANDLE __stdcall ApiTools::OpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId ) {

	return ::OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId );
}