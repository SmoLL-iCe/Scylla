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

BOOL DumpProcessW( const wchar_t* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const wchar_t* pFileResult );

BOOL WINAPI ScyllaDumpCurrentProcessW( const wchar_t* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const wchar_t* pFileResult );
BOOL WINAPI ScyllaDumpCurrentProcessA( const char* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const char* pFileResult );

BOOL WINAPI ScyllaDumpProcessW( std::uintptr_t pid, const wchar_t* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const wchar_t* pFileResult );
BOOL WINAPI ScyllaDumpProcessA( std::uintptr_t pid, const char* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const char* pFileResult );

BOOL WINAPI ScyllaRebuildFileW( const wchar_t* pFileToRebuild, BOOL bRemoveDosStub, BOOL bUpdatePeHeaderChecksum, BOOL bCreateBackup );
BOOL WINAPI ScyllaRebuildFileA( const char* pFileToRebuild, BOOL bRemoveDosStub, BOOL bUpdatePeHeaderChecksum, BOOL bCreateBackup );

int WINAPI ScyllaIatSearch( std::uint32_t uProcessId, std::uintptr_t* pIatStart, std::uint32_t* pIatSize, std::uintptr_t uSearchStart, BOOL bAdvancedSearch );
int WINAPI ScyllaIatFixAutoW( std::uintptr_t uIatAddr, std::uint32_t uIatSize, std::uint32_t uProcessId, const wchar_t* pDumpFile, const wchar_t* pIatFixFile );
