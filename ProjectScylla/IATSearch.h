#pragma once

#include "ApiReader.h"
#include <set>

class IATSearch : protected ApiReader
{
public:

	std::uintptr_t uMemoryAddress;
	std::size_t szMemorySize;

	bool searchImportAddressTableInProcess( std::uintptr_t uStartAddress, std::uintptr_t* uAddressIAT, std::uint32_t* uSizeIAT, bool advanced );

private:

	std::uintptr_t findAPIAddressInIAT( std::uintptr_t uStartAddress );
	bool findIATAdvanced( std::uintptr_t uStartAddress, std::uintptr_t* uAddressIAT, std::uint32_t* uSizeIAT );
	std::uintptr_t findNextFunctionAddress( );
	std::uintptr_t findIATPointer( );

	bool isIATPointerValid( std::uintptr_t uIatPointer, bool bCheckRedirects );

	bool findIATStartAndSize( std::uintptr_t uAddress, std::uintptr_t* uAddressIAT, std::uint32_t* uSizeIAT );

	std::uintptr_t findIATStartAddress( std::uintptr_t uBaseAddress, std::uintptr_t uStartAddress, std::uint8_t* pDataBuffer );
	std::uint32_t findIATSize( std::uintptr_t uBaseAddress, std::uintptr_t uIATAddress, std::uint8_t* pDataBuffer, std::uint32_t uBufferSize );

	void findIATPointers( std::set<std::uintptr_t>& iatPointers );
	void findExecutableMemoryPagesByStartAddress( std::uintptr_t uStartAddress, std::uintptr_t* uBaseAddress, std::size_t* pMemorySize );
	void filterIATPointersList( std::set<std::uintptr_t>& iatPointers );
	void getMemoryBaseAndSizeForIat( std::uintptr_t uAddress, std::uintptr_t* uBaseAddress, std::uint32_t* pBaseSize );
};
