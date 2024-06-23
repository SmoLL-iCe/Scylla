#pragma once
#include "ApiTools.h"
#include <fstream>
#include "ntos.h"
#include "../Tools/Logs.h"

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

HANDLE __stdcall ApiTools::OpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId ) {

	HANDLE hProcess = 0;

	CLIENT_ID cid = { 0 };

	OBJECT_ATTRIBUTES ObjectAttributes{};

	InitializeObjectAttributes( &ObjectAttributes, 0, 0, 0, 0 );
	cid.UniqueProcess = reinterpret_cast<HANDLE>( static_cast<size_t>( dwProcessId ) );

	NTSTATUS ntStatus = NtOpenProcess( &hProcess, dwDesiredAccess, &ObjectAttributes, &cid );

	if ( NT_SUCCESS( ntStatus ) )
	{
		return hProcess;
	}

	//LOGS_DEBUG( "NtOpenProcess :: Failed to open handle, PID %X Error 0x%X", dwProcessId, RtlNtStatusToDosError( ntStatus ) );

	// I have already failed using the native NtOpenProcess, but not the wrapped OpenProcess

	return ::OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId );
}

BOOL __stdcall ApiTools::IsWow64Process( HANDLE hProcess, PBOOL Wow64Process ) {

	ULONG ReturnLength = 0;
	PVOID pWow64Process = nullptr;
	NTSTATUS status = ApiTools::QueryInformationProcess( hProcess, ProcessWow64Information, &pWow64Process, sizeof( pWow64Process ), &ReturnLength );

	if ( status == 0 && pWow64Process != nullptr ) {
		*Wow64Process = TRUE;
	}
	else {
		*Wow64Process = FALSE;
	}
	return status == 0;
}

std::unique_ptr<void, VirtualFreeDeleter> ApiTools::GetSystemInfo( SYSTEM_INFORMATION_CLASS SystemInformationClass ) {
	ULONG uBufferSize = 0x1000 * 10;

	// Use smart pointer with custom deleter
	auto pBuffer = std::unique_ptr<void, VirtualFreeDeleter>(
		VirtualAlloc( nullptr, uBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );

	if ( !pBuffer ) return nullptr;

	NTSTATUS Status = 0;

	while ( true ) {
		Status = NtQuerySystemInformation( SystemInformationClass, pBuffer.get( ), uBufferSize, &uBufferSize );

		if ( Status == STATUS_INFO_LENGTH_MISMATCH || Status == STATUS_BUFFER_TOO_SMALL ) {
			// Release and reallocate buffer
			pBuffer.reset( VirtualAlloc( nullptr, uBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
			if ( !pBuffer ) return nullptr;
		}
		else {
			break;
		}
	}

	if ( !NT_SUCCESS( Status ) ) {
		return nullptr;
	}

	return pBuffer;
}

// ========================================================================================================
// ========================================================================================================
// ========================================================================================================
// NATIVE CALLS
// ========================================================================================================
// ========================================================================================================
// ========================================================================================================

void ApiTools::CloseHandle( HANDLE hObject ) {
	::NtClose( hObject );
}

LPVOID __stdcall ApiTools::VirtualAllocEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect )
{
	PVOID pAddress = lpAddress;

	SIZE_T Size = dwSize;

	const NTSTATUS Status = NtAllocateVirtualMemory( hProcess, &pAddress, 0, &Size, flAllocationType, flProtect );

	return  ( Status == 0 ) ? pAddress : nullptr;
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
	return NtWriteVirtualMemory( hProcess, lpBaseAddress, const_cast<LPVOID>(lpBuffer), nSize, lpNumberOfBytesWritten ) == 0;
}

NTSTATUS __stdcall ApiTools::QueryInformationProcess( HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength ) {

	return NtQueryInformationProcess( ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength );
}