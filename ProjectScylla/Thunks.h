#pragma once

#include <windows.h>
#include <map>
#include <cstdint>

class ImportThunk
{
public:
	wchar_t pModuleName[ MAX_PATH ];
	char name[ MAX_PATH ];
	std::uintptr_t uVA;
	std::uintptr_t uRVA;
	std::uint16_t uOrdinal;
	std::uintptr_t uApiAddressVA;
	std::uint16_t uHint;
	bool bValid;
	bool bSuspect;

	std::uintptr_t uKey;

	void invalidate( );
};

class ImportModuleThunk
{
public:
	wchar_t pModuleName[ MAX_PATH ];
	std::map<std::uintptr_t, ImportThunk> mpThunkList;

	std::uintptr_t uFirstThunk;

	std::uintptr_t uKey;

	std::uintptr_t getFirstThunk( ) const;

	bool isValid( ) const;
};
