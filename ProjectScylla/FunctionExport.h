#pragma once

#include <cstdint>
#include <windows.h>

const int SCY_ERROR_SUCCESS = 0;
const int SCY_ERROR_PROCOPEN = -1;
const int SCY_ERROR_IATWRITE = -2;
const int SCY_ERROR_IATSEARCH = -3;
const int SCY_ERROR_IATNOTFOUND = -4;
const int SCY_ERROR_PIDNOTFOUND = -5;

//function to export in DLL

BOOL DumpProcessW( const wchar_t* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const wchar_t* fileResult );

BOOL WINAPI ScyllaDumpCurrentProcessW( const wchar_t* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const wchar_t* fileResult );
BOOL WINAPI ScyllaDumpCurrentProcessA( const char* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const char* fileResult );

BOOL WINAPI ScyllaDumpProcessW( std::uintptr_t pid, const wchar_t* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const wchar_t* fileResult );
BOOL WINAPI ScyllaDumpProcessA( std::uintptr_t pid, const char* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const char* fileResult );

BOOL WINAPI ScyllaRebuildFileW( const wchar_t* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup );
BOOL WINAPI ScyllaRebuildFileA( const char* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup );

int WINAPI ScyllaIatSearch( std::uint32_t dwProcessId, std::uintptr_t* iatStart, std::uint32_t* pIatSize, std::uintptr_t searchStart, BOOL advancedSearch );
int WINAPI ScyllaIatFixAutoW( std::uintptr_t iatAddr, std::uint32_t pIatSize, std::uint32_t dwProcessId, const wchar_t* dumpFile, const wchar_t* iatFixFile );
