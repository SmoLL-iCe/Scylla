#include "IATSearch.h"
#include "Architecture.h"
#include "Tools/Logs.h"
#include "WinApi/ApiTools.h"

bool IATSearch::searchImportAddressTableInProcess( std::uintptr_t uStartAddress, std::uintptr_t* uAddressIAT, std::uint32_t* uSizeIAT, bool advanced ) {
	if ( advanced ) {
		return findIATAdvanced( uStartAddress, uAddressIAT, uSizeIAT );
	}

	auto uAddressInIAT = findAPIAddressInIAT( uStartAddress );

	if ( !uAddressInIAT ) {
		LOGS_DEBUG( "searchImportAddressTableInProcess :: uAddressInIAT not found, uStartAddress %p", uStartAddress );
		return false;
	}

	return findIATStartAndSize( uAddressInIAT, uAddressIAT, uSizeIAT );
}

bool IATSearch::findIATAdvanced( std::uintptr_t uStartAddress, std::uintptr_t* uAddressIAT, std::uint32_t* uSizeIAT ) {

	std::uintptr_t uBaseAddress = 0;
	std::size_t szMemorySize = 0;
	findExecutableMemoryPagesByStartAddress( uStartAddress, &uBaseAddress, &szMemorySize );

	if ( szMemorySize == 0 )
		return false;

	auto pDataBuffer = std::make_unique<std::uint8_t[ ]>( szMemorySize );

	if ( !readMemoryFromProcess( uBaseAddress, szMemorySize, pDataBuffer.get( ) ) ) {
		LOGS_DEBUG( "findAPIAddressInIAT2 :: error reading memory" );
		return false;
	}

	std::set<std::uintptr_t> iatPointers;
	std::uint8_t* pTempBuf = pDataBuffer.get( );
	std::uintptr_t next;
	while ( decomposeMemory( pTempBuf, szMemorySize, uBaseAddress ) && uDecomposerInstructionsCount != 0 ) {
		findIATPointers( iatPointers );

		next = static_cast<std::uintptr_t>( decomposerResult[ uDecomposerInstructionsCount - 1 ].addr - uBaseAddress ) + decomposerResult[ uDecomposerInstructionsCount - 1 ].size;
		pTempBuf += next;

		if ( szMemorySize <= next )
			break;

		szMemorySize -= next;
		uBaseAddress += next;
	}

	if ( iatPointers.empty( ) )
		return false;

	filterIATPointersList( iatPointers );
	if ( iatPointers.empty( ) )
		return false;

	*uAddressIAT = *iatPointers.begin( );
	*uSizeIAT = static_cast<std::uint32_t>( *--iatPointers.end( ) - *iatPointers.begin( ) + sizeof( std::uintptr_t ) );

	if ( *uSizeIAT > 2000000 * sizeof( std::uintptr_t ) ) {
		*uAddressIAT = 0;
		*uSizeIAT = 0;
		return false;
	}

	LOGS( "IAT Search Adv: Found %zu (0x%X) possible IAT entries.", iatPointers.size( ), iatPointers.size( ) );
	LOGS( "IAT Search Adv: Possible IAT first %p last %p entry.", *iatPointers.begin( ), *--iatPointers.end( ) );

	return true;
}

std::uintptr_t IATSearch::findAPIAddressInIAT( std::uintptr_t uStartAddress )
{
	const std::size_t MEMORY_READ_SIZE = 200;
	std::uint8_t pDataBuffer[ MEMORY_READ_SIZE ] { };

	std::uintptr_t uIatPointer = 0;
	int nCounter = 0;

	// to detect stolen api
	uMemoryAddress = 0;
	szMemorySize = 0;

	do
	{
		nCounter++;

		if ( !readMemoryFromProcess( uStartAddress, sizeof( pDataBuffer ), pDataBuffer ) )
		{

			LOGS_DEBUG( "findAPIAddressInIAT :: error reading memory " PRINTF_DWORD_PTR_FULL_S, uStartAddress );

			return 0;
		}

		if ( decomposeMemory( pDataBuffer, sizeof( pDataBuffer ), uStartAddress ) )
		{
			uIatPointer = findIATPointer( );
			if ( uIatPointer )
			{
				if ( isIATPointerValid( uIatPointer, true ) )
				{
					return uIatPointer;
				}
			}
		}

		uStartAddress = findNextFunctionAddress( );
		//printf("uStartAddress %08X\n",uStartAddress);
	} while ( uStartAddress != 0 && nCounter != 8 );

	return 0;
}

std::uintptr_t IATSearch::findNextFunctionAddress( )
{
	_DecodedInst inst;

	for ( std::uint32_t i = 0; i < uDecomposerInstructionsCount; i++ )
	{

		if ( decomposerResult[ i ].flags == FLAG_NOT_DECODABLE )
			continue;

		if ( META_GET_FC( decomposerResult[ i ].meta ) != FC_CALL && META_GET_FC( decomposerResult[ i ].meta ) != FC_UNC_BRANCH )
			continue;

		if ( decomposerResult[ i ].size < 5 )
			continue;

		if ( decomposerResult[ i ].ops[ 0 ].type == O_PC )
		{
			distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
			LOGS_DEBUG( "%S %S %d %d - target uAddress: " PRINTF_DWORD_PTR_FULL_S, inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, INSTRUCTION_GET_TARGET( &decomposerResult[ i ] ) );

			return static_cast<std::uintptr_t>( INSTRUCTION_GET_TARGET( &decomposerResult[ i ] ) );
		}
		
	}

	return 0;
}

std::uintptr_t IATSearch::findIATPointer( )
{
	_DecodedInst inst;

	for ( std::uint32_t i = 0; i < uDecomposerInstructionsCount; i++ )
	{
		if ( decomposerResult[ i ].flags == FLAG_NOT_DECODABLE )
			continue;

		if ( META_GET_FC( decomposerResult[ i ].meta ) != FC_CALL && META_GET_FC( decomposerResult[ i ].meta ) != FC_UNC_BRANCH )
			continue;

		if ( decomposerResult[ i ].size < 5 )
			continue;

		if ( ProcessAccessHelp::is64BitProcess ) { 

			if ( decomposerResult[ i ].flags & FLAG_RIP_RELATIVE )
			{
				distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
				LOGS_DEBUG( "%S %S %d %d - target uAddress: " PRINTF_DWORD_PTR_FULL_S, inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] ) );

				return INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] );
			}
		}
		else
		{
			if ( decomposerResult[ i ].ops[ 0 ].type == O_DISP )
			{
				//jmp dword ptr || call dword ptr

				distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
				LOGS_DEBUG( "%S %S %d %d - target uAddress: " PRINTF_DWORD_PTR_FULL_S, inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, static_cast<std::uintptr_t>( decomposerResult[ i ].disp ) );

				return static_cast<std::uintptr_t>( decomposerResult[ i ].disp );
			}
		}
	}

	return 0;
}

bool IATSearch::isIATPointerValid( std::uintptr_t uIatPointer, bool bCheckRedirects )
{
	std::uintptr_t uApiAddress = 0;

	if ( !readMemoryFromProcess( uIatPointer, sizeof( uApiAddress ), &uApiAddress ) )
	{
		LOGS_DEBUG( "isIATPointerValid :: error reading memory" );
		return false;
	}

	//printf("Win api ? %08X\n",uApiAddress);

	if ( isApiAddressValid( uApiAddress ) != 0 )
	{
		return true;
	}

	if ( bCheckRedirects )
	{
		//maybe redirected import?
		//if the uAddress is 2 times inside a memory region it is possible a redirected api
		if ( uApiAddress > uMemoryAddress && uApiAddress < ( uMemoryAddress + szMemorySize ) )
		{
			return true;
		}

		getMemoryRegionFromAddress( uApiAddress, &uMemoryAddress, &szMemorySize );
	}

	return false;
}

bool IATSearch::findIATStartAndSize( std::uintptr_t uAddress, std::uintptr_t* uAddressIAT, std::uint32_t* uSizeIAT ) {
	std::uintptr_t uBaseAddress = 0;
	std::uint32_t uBaseSize = 0;

	getMemoryBaseAndSizeForIat( uAddress, &uBaseAddress, &uBaseSize );

	if ( !uBaseAddress ) {
		return false;
	}

	auto pDataBuffer = std::make_unique<std::uint8_t[ ]>( uBaseSize * sizeof( std::uintptr_t ) * 3 );

	std::memset( pDataBuffer.get( ), 0, uBaseSize * sizeof( std::uintptr_t ) * 3 );

	if ( !readMemoryFromProcess( uBaseAddress, uBaseSize, pDataBuffer.get( ) ) ) {

		LOGS_DEBUG( "findIATStartAddress :: error reading memory" );

		return false;
	}

	*uAddressIAT = findIATStartAddress( uBaseAddress, uAddress, pDataBuffer.get( ) );

	*uSizeIAT = findIATSize( uBaseAddress, *uAddressIAT, pDataBuffer.get( ), uBaseSize );

	return true;
}

std::uintptr_t IATSearch::findIATStartAddress( std::uintptr_t uBaseAddress, std::uintptr_t uStartAddress, std::uint8_t* pDataBuffer ) {

	auto pIATAddress = reinterpret_cast<std::uintptr_t*>( uStartAddress - uBaseAddress + reinterpret_cast<std::uintptr_t>( pDataBuffer ) );

	while ( reinterpret_cast<std::uintptr_t>( pIATAddress ) != reinterpret_cast<std::uintptr_t>( pDataBuffer ) ) {

		if ( isInvalidMemoryForIat( *pIATAddress ) ) {

			if ( pIATAddress - 1 >= reinterpret_cast<std::uintptr_t*>( pDataBuffer ) ) {

				if ( isInvalidMemoryForIat( *( pIATAddress - 1 ) ) ) {

					if ( pIATAddress - 2 >= reinterpret_cast<std::uintptr_t*>( pDataBuffer ) ) {

						if ( !isApiAddressValid( *( pIATAddress - 2 ) ) ) {
							return reinterpret_cast<std::uintptr_t>( pIATAddress ) - reinterpret_cast<std::uintptr_t>( pDataBuffer ) + uBaseAddress;
						}
					}
				}
			}
		}
		pIATAddress--;
	}

	return uBaseAddress;
}

std::uint32_t IATSearch::findIATSize( std::uintptr_t uBaseAddress, std::uintptr_t uIATAddress, std::uint8_t* pDataBuffer, std::uint32_t uBufferSize ) {

	auto pIATAddress = reinterpret_cast<std::uintptr_t*>( uIATAddress - uBaseAddress + reinterpret_cast<std::uintptr_t>( pDataBuffer ) );

	LOGS_DEBUG( "findIATSize :: uBaseAddress %X uIATAddress %X pDataBuffer %X pIATAddress %X", uBaseAddress, uIATAddress, pDataBuffer, pIATAddress );

	while ( reinterpret_cast<std::uintptr_t>( pIATAddress ) < ( reinterpret_cast<std::uintptr_t>( pDataBuffer ) + uBufferSize - 1 ) ) {

		LOGS_DEBUG( "findIATSize :: %X %X %X", pIATAddress, *pIATAddress, *( pIATAddress + 1 ) );

		if ( isInvalidMemoryForIat( *pIATAddress ) ) {

			if ( isInvalidMemoryForIat( *( pIATAddress + 1 ) ) ) {

				if ( !isApiAddressValid( *( pIATAddress + 2 ) ) ) {

					return static_cast<std::uint32_t>( reinterpret_cast<std::uintptr_t>( pIATAddress ) - reinterpret_cast<std::uintptr_t>( pDataBuffer ) - ( uIATAddress - uBaseAddress ) );
				}
			}
		}

		pIATAddress++;
	}

	return uBufferSize;
}

void IATSearch::findIATPointers( std::set<std::uintptr_t>& iatPointers )
{
	_DecodedInst inst;

	for ( std::uint32_t i = 0; i < uDecomposerInstructionsCount; i++ )
	{
		if ( decomposerResult[ i ].flags == FLAG_NOT_DECODABLE )
			continue;

		if ( META_GET_FC( decomposerResult[ i ].meta ) != FC_CALL && META_GET_FC( decomposerResult[ i ].meta ) != FC_UNC_BRANCH )
			continue;

		if ( decomposerResult[ i ].size < 5 )
			continue;
				
		if ( ProcessAccessHelp::is64BitProcess )
		{
			if ( decomposerResult[ i ].flags & FLAG_RIP_RELATIVE )
			{
				distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
				LOGS_DEBUG( "%S %S %d %d - target uAddress: " PRINTF_DWORD_PTR_FULL_S,
					inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] ) );

				iatPointers.insert( INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] ) );
			}
		}
		else { 
			if ( decomposerResult[ i ].ops[ 0 ].type == O_DISP )
			{
				//jmp dword ptr || call dword ptr

				distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
				LOGS_DEBUG( "%S %S %d %d - target uAddress: " PRINTF_DWORD_PTR_FULL_S,
					inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, static_cast<std::uintptr_t>( decomposerResult[ i ].disp ) );

				iatPointers.insert( static_cast<std::uintptr_t>( decomposerResult[ i ].disp ) );
			}
		}
	}
}

void IATSearch::findExecutableMemoryPagesByStartAddress( std::uintptr_t uStartAddress, std::uintptr_t* uBaseAddress, std::size_t* pMemorySize )
{
	MEMORY_BASIC_INFORMATION memBasic {};
	*pMemorySize = 0;
	*uBaseAddress = 0;

	if ( ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( uStartAddress ), &memBasic, sizeof( memBasic ) ) != sizeof( memBasic ) )
	{
		LOGS_DEBUG( "findIATStartAddress :: VirtualQueryEx error %u", GetLastError( ) );
		return;
	}

	// Search downwards to find the base uAddress
	do
	{
		*pMemorySize = memBasic.RegionSize;
		*uBaseAddress = reinterpret_cast<std::uintptr_t>( memBasic.BaseAddress );
		std::uintptr_t uTempAddress = *uBaseAddress - 1;

		if ( ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( uTempAddress ), &memBasic, sizeof( memBasic ) ) != sizeof( memBasic ) )
		{
			break;
		}
	} while ( isPageExecutable( memBasic.Protect ) );

	// Search upwards to calculate total size of executable memory
	std::uintptr_t uTempAddress = *uBaseAddress;
	*pMemorySize = 0;

	do
	{
		uTempAddress += memBasic.RegionSize;
		*pMemorySize += memBasic.RegionSize;

		if ( ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( uTempAddress ), &memBasic, sizeof( memBasic ) ) != sizeof( memBasic ) )
		{
			break;
		}
	} while ( isPageExecutable( memBasic.Protect ) );
}

void IATSearch::filterIATPointersList( std::set<std::uintptr_t>& iatPointers ) {

	if ( iatPointers.size( ) <= 2 ) {
		return;
	}

	auto iter = iatPointers.begin( );
	std::advance( iter, iatPointers.size( ) / 2 ); //start in the middle, important!
	std::uintptr_t uLastPointer = *iter++;

	for ( ; iter != iatPointers.end( );) {
		if ( ( *iter - uLastPointer ) > 0x100 && ( !isIATPointerValid( uLastPointer, false ) || !isIATPointerValid( *iter, false ) ) ) {
			iatPointers.erase( iter, iatPointers.end( ) );
			break;
		}
		uLastPointer = *iter++;
	}

	if ( iatPointers.empty( ) ) {
		return;
	}

	//delete bad code pointers.

	bool erased;
	do {
		erased = false;
		for ( auto it = iatPointers.begin( ); it != iatPointers.end( ) && next( it ) != iatPointers.end( );) {
			auto nextIt = next( it );
			if ( ( *nextIt - *it ) > 0x100 ) { //check pointer difference, a typical difference is 4 on 32bit systems
				if ( !isIATPointerValid( *it, false ) ) {
					it = iatPointers.erase( it );
					erased = true;
				}
				else if ( !isIATPointerValid( *nextIt, false ) ) {
					iatPointers.erase( nextIt );
					erased = true;
				}
				else {
					++it;
				}
			}
			else {
				++it;
			}
		}
	} while ( erased && iatPointers.size( ) > 1 );
}

//A big section size is a common anti-debug/anti-dump trick, limit the max size to 100 000 000 bytes

static void adjustSizeForBigSections( std::uint32_t* uBadValue )
{
	if ( *uBadValue > 100000000 )
	{
		*uBadValue = 100000000;
	}
}

static bool isSectionSizeTooBig( std::size_t uSectionSize ) {
	return ( uSectionSize > 100000000 );
}

void IATSearch::getMemoryBaseAndSizeForIat( std::uintptr_t uAddress, std::uintptr_t* uBaseAddress, std::uint32_t* pBaseSize ) {
	MEMORY_BASIC_INFORMATION memBasic1 {};
	MEMORY_BASIC_INFORMATION memBasic2 {};
	MEMORY_BASIC_INFORMATION memBasic3 {};

	if ( !ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( uAddress ), &memBasic2, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
		return;
	}

	*uBaseAddress = reinterpret_cast<std::uintptr_t>( memBasic2.BaseAddress );
	*pBaseSize = static_cast<std::uint32_t>( memBasic2.RegionSize );

	adjustSizeForBigSections( pBaseSize );

	// Get the neighbors
	if ( !ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( *uBaseAddress - 1 ), &memBasic1, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
		return;
	}
	if ( !ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( *uBaseAddress + memBasic2.RegionSize ), &memBasic3, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
		return;
	}

	if ( memBasic3.State != MEM_COMMIT || memBasic1.State != MEM_COMMIT || ( memBasic3.Protect & PAGE_NOACCESS ) || ( memBasic1.Protect & PAGE_NOACCESS ) ) {
		return;
	}

	if ( isSectionSizeTooBig( memBasic1.RegionSize ) || isSectionSizeTooBig( memBasic2.RegionSize ) || isSectionSizeTooBig( memBasic3.RegionSize ) ) {
		return;
	}

	std::uintptr_t start = reinterpret_cast<std::uintptr_t>( memBasic1.BaseAddress );
	std::uintptr_t end = reinterpret_cast<std::uintptr_t>( memBasic3.BaseAddress ) + memBasic3.RegionSize;

	*uBaseAddress = start;
	*pBaseSize = static_cast<std::uint32_t>( end - start );
}
