#include "IATSearch.h"
#include "Architecture.h"
#include "Tools/Logs.h"
#include "WinApi/ApiTools.h"

bool IATSearch::searchImportAddressTableInProcess( DWORD_PTR startAddress, DWORD_PTR* addressIAT, DWORD* sizeIAT, bool advanced ) {
	if ( advanced ) {
		return findIATAdvanced( startAddress, addressIAT, sizeIAT );
	}

	auto addressInIAT = findAPIAddressInIAT( startAddress );
	if ( !addressInIAT ) {
		LOGS_DEBUG( "searchImportAddressTableInProcess :: addressInIAT not found, startAddress %p", startAddress );
		return false;
	}

	return findIATStartAndSize( addressInIAT, addressIAT, sizeIAT );
}

bool IATSearch::findIATAdvanced( DWORD_PTR startAddress, DWORD_PTR* addressIAT, DWORD* sizeIAT ) {

	DWORD_PTR baseAddress = 0;
	SIZE_T memorySize = 0;
	findExecutableMemoryPagesByStartAddress( startAddress, &baseAddress, &memorySize );

	if ( memorySize == 0 ) 
		return false;

	auto dataBuffer = std::make_unique<BYTE[ ]>( memorySize );

	if ( !readMemoryFromProcess( baseAddress, memorySize, dataBuffer.get( ) ) ) {
		LOGS_DEBUG( "findAPIAddressInIAT2 :: error reading memory" );
		return false;
	}

	std::set<DWORD_PTR> iatPointers;
	BYTE* tempBuf = dataBuffer.get( );
	DWORD_PTR next;
	while ( decomposeMemory( tempBuf, memorySize, baseAddress ) && decomposerInstructionsCount != 0 ) {
		findIATPointers( iatPointers );

		next = static_cast<DWORD_PTR>( decomposerResult[ decomposerInstructionsCount - 1 ].addr - baseAddress ) + decomposerResult[ decomposerInstructionsCount - 1 ].size;
		tempBuf += next;

		if ( memorySize <= next ) 
			break;

		memorySize -= next;
		baseAddress += next;
	}

	if ( iatPointers.empty( ) ) 
		return false;

	filterIATPointersList( iatPointers );
	if ( iatPointers.empty( ) ) 
		return false;

	*addressIAT = *iatPointers.begin( );
	*sizeIAT = static_cast<DWORD>( *--iatPointers.end( ) - *iatPointers.begin( ) + sizeof( DWORD_PTR ) );

	if ( *sizeIAT > 2000000 * sizeof( DWORD_PTR ) ) {
		*addressIAT = 0;
		*sizeIAT = 0;
		return false;
	}

	LOGS( "IAT Search Adv: Found %zu (0x%X) possible IAT entries.", iatPointers.size( ), iatPointers.size( ) );
	LOGS( "IAT Search Adv: Possible IAT first %p last %p entry.", *iatPointers.begin( ), *--iatPointers.end( ) );

	return true;
}

DWORD_PTR IATSearch::findAPIAddressInIAT( DWORD_PTR startAddress )
{
	const size_t MEMORY_READ_SIZE = 200;
	BYTE dataBuffer[ MEMORY_READ_SIZE ]{ };

	DWORD_PTR iatPointer = 0;
	int counter = 0;

	// to detect stolen api
	memoryAddress = 0;
	memorySize = 0;

	do
	{
		counter++;

		if ( !readMemoryFromProcess( startAddress, sizeof( dataBuffer ), dataBuffer ) )
		{

			LOGS_DEBUG( "findAPIAddressInIAT :: error reading memory " PRINTF_DWORD_PTR_FULL_S, startAddress );

			return 0;
		}

		if ( decomposeMemory( dataBuffer, sizeof( dataBuffer ), startAddress ) )
		{
			iatPointer = findIATPointer( );
			if ( iatPointer )
			{
				if ( isIATPointerValid( iatPointer, true ) )
				{
					return iatPointer;
				}
			}
		}

		startAddress = findNextFunctionAddress( );
		//printf("startAddress %08X\n",startAddress);
	} while ( startAddress != 0 && counter != 8 );

	return 0;
}

DWORD_PTR IATSearch::findNextFunctionAddress( )
{

	_DecodedInst inst;


	for ( unsigned int i = 0; i < decomposerInstructionsCount; i++ )
	{

		if ( decomposerResult[ i ].flags != FLAG_NOT_DECODABLE )
		{
			if ( META_GET_FC( decomposerResult[ i ].meta ) == FC_CALL || META_GET_FC( decomposerResult[ i ].meta ) == FC_UNC_BRANCH )
			{
				if ( decomposerResult[ i ].size >= 5 )
				{
					if ( decomposerResult[ i ].ops[ 0 ].type == O_PC )
					{

						distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
						LOGS_DEBUG( "%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, INSTRUCTION_GET_TARGET( &decomposerResult[ i ] ) );

						return static_cast<DWORD_PTR>(INSTRUCTION_GET_TARGET( &decomposerResult[ i ] ));
					}
				}
			}
		}
	}

	return 0;
}

DWORD_PTR IATSearch::findIATPointer( )
{

	_DecodedInst inst;


	for ( unsigned int i = 0; i < decomposerInstructionsCount; i++ )
	{
		if ( decomposerResult[ i ].flags != FLAG_NOT_DECODABLE )
		{
			if ( META_GET_FC( decomposerResult[ i ].meta ) == FC_CALL || META_GET_FC( decomposerResult[ i ].meta ) == FC_UNC_BRANCH )
			{
				if ( decomposerResult[ i ].size >= 5 )
				{
#ifdef _WIN64
					if ( decomposerResult[ i ].flags & FLAG_RIP_RELATIVE )
					{

						distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
						LOGS_DEBUG( "%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] ) );

						return INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] );
					}
#else
					if ( decomposerResult[ i ].ops[ 0 ].type == O_DISP )
					{
						//jmp dword ptr || call dword ptr

						distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
						LOGS_DEBUG( "%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, static_cast<DWORD_PTR>( decomposerResult[ i ].disp ) );

						return static_cast<DWORD_PTR>( decomposerResult[ i ].disp );
					}
#endif

				}
			}
		}
	}

	return 0;
}

bool IATSearch::isIATPointerValid( DWORD_PTR iatPointer, bool checkRedirects )
{
	DWORD_PTR apiAddress = 0;

	if ( !readMemoryFromProcess( iatPointer, sizeof( apiAddress ), &apiAddress ) )
	{
		LOGS_DEBUG( "isIATPointerValid :: error reading memory" );
		return false;
	}

	//printf("Win api ? %08X\n",apiAddress);

	if ( isApiAddressValid( apiAddress ) != 0 )
	{
		return true;
	}

	if ( checkRedirects )
	{
		//maybe redirected import?
		//if the address is 2 times inside a memory region it is possible a redirected api
		if ( apiAddress > memoryAddress && apiAddress < ( memoryAddress + memorySize ) )
		{
			return true;
		}

		getMemoryRegionFromAddress( apiAddress, &memoryAddress, &memorySize );
	}

	return false;
}

bool IATSearch::findIATStartAndSize( DWORD_PTR address, DWORD_PTR* addressIAT, DWORD* sizeIAT ) {
	DWORD_PTR baseAddress = 0;
	DWORD baseSize = 0;

	getMemoryBaseAndSizeForIat( address, &baseAddress, &baseSize );

	if ( !baseAddress ) {
		return false;
	}

	auto dataBuffer = std::make_unique<BYTE[ ]>( baseSize * sizeof( DWORD_PTR ) * 3 );

	std::memset( dataBuffer.get( ), 0, baseSize * sizeof( DWORD_PTR ) * 3 );

	if ( !readMemoryFromProcess( baseAddress, baseSize, dataBuffer.get( ) ) ) {

		LOGS_DEBUG( "findIATStartAddress :: error reading memory" );

		return false;
	}

	*addressIAT = findIATStartAddress( baseAddress, address, dataBuffer.get( ) );

	*sizeIAT = findIATSize( baseAddress, *addressIAT, dataBuffer.get( ), baseSize );

	return true;
}

DWORD_PTR IATSearch::findIATStartAddress( DWORD_PTR baseAddress, DWORD_PTR startAddress, BYTE* dataBuffer ) {

	auto pIATAddress = reinterpret_cast<DWORD_PTR*>( startAddress - baseAddress + reinterpret_cast<DWORD_PTR>( dataBuffer ) );

	while ( reinterpret_cast<DWORD_PTR>( pIATAddress ) != reinterpret_cast<DWORD_PTR>( dataBuffer ) ) {

		if ( isInvalidMemoryForIat( *pIATAddress ) ) {

			if ( pIATAddress - 1 >= reinterpret_cast<DWORD_PTR*>( dataBuffer ) ) {

				if ( isInvalidMemoryForIat( *( pIATAddress - 1 ) ) ) {

					if ( pIATAddress - 2 >= reinterpret_cast<DWORD_PTR*>( dataBuffer ) ) {

						if ( !isApiAddressValid( *( pIATAddress - 2 ) ) ) {
							return reinterpret_cast<DWORD_PTR>( pIATAddress ) - reinterpret_cast<DWORD_PTR>( dataBuffer ) + baseAddress;
						}
					}
				}
			}
		}
		pIATAddress--;
	}

	return baseAddress;
}

DWORD IATSearch::findIATSize( DWORD_PTR baseAddress, DWORD_PTR iatAddress, BYTE* dataBuffer, DWORD bufferSize ) {

	auto pIATAddress = reinterpret_cast<DWORD_PTR*>( iatAddress - baseAddress + reinterpret_cast<DWORD_PTR>( dataBuffer ) );

	LOGS_DEBUG( "findIATSize :: baseAddress %X iatAddress %X dataBuffer %X pIATAddress %X", baseAddress, iatAddress, dataBuffer, pIATAddress );

	while ( reinterpret_cast<DWORD_PTR>( pIATAddress ) < ( reinterpret_cast<DWORD_PTR>( dataBuffer ) + bufferSize - 1 ) ) {

		LOGS_DEBUG( "findIATSize :: %X %X %X", pIATAddress, *pIATAddress, *( pIATAddress + 1 ) );

		if ( isInvalidMemoryForIat( *pIATAddress ) ) {

			if ( isInvalidMemoryForIat( *( pIATAddress + 1 ) ) ) {

				if ( !isApiAddressValid( *( pIATAddress + 2 ) ) ) {

					return static_cast<DWORD>( reinterpret_cast<DWORD_PTR>( pIATAddress ) - reinterpret_cast<DWORD_PTR>( dataBuffer ) - ( iatAddress - baseAddress ) );
				}
			}
		}

		pIATAddress++;
	}

	return bufferSize;
}

void IATSearch::findIATPointers( std::set<DWORD_PTR>& iatPointers )
{
	_DecodedInst inst;

	for ( unsigned int i = 0; i < decomposerInstructionsCount; i++ )
	{
		if ( decomposerResult[ i ].flags != FLAG_NOT_DECODABLE )
		{
			if ( META_GET_FC( decomposerResult[ i ].meta ) == FC_CALL || META_GET_FC( decomposerResult[ i ].meta ) == FC_UNC_BRANCH )
			{
				if ( decomposerResult[ i ].size >= 5 )
				{
#ifdef _WIN64
					if ( decomposerResult[ i ].flags & FLAG_RIP_RELATIVE )
					{
						distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
						LOGS_DEBUG( "%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, 
							inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] ) );

						iatPointers.insert( INSTRUCTION_GET_RIP_TARGET( &decomposerResult[ i ] ) );
					}
#else
					if ( decomposerResult[ i ].ops[ 0 ].type == O_DISP )
					{
						//jmp dword ptr || call dword ptr

						distorm_format( &decomposerCi, &decomposerResult[ i ], &inst );
						LOGS_DEBUG( "%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, 
							inst.mnemonic.p, inst.operands.p, decomposerResult[ i ].ops[ 0 ].type, decomposerResult[ i ].size, static_cast<DWORD_PTR>( decomposerResult[ i ].disp ) );

						iatPointers.insert( static_cast<DWORD_PTR>( decomposerResult[ i ].disp ) );
					}
#endif
				}
			}
		}
	}
}

void IATSearch::findExecutableMemoryPagesByStartAddress( DWORD_PTR startAddress, DWORD_PTR* baseAddress, SIZE_T* memorySize )
{
	MEMORY_BASIC_INFORMATION memBasic{};
	*memorySize = 0;
	*baseAddress = 0;

	if ( ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( startAddress ), &memBasic, sizeof( memBasic ) ) != sizeof( memBasic ) )
	{
		LOGS_DEBUG( "findIATStartAddress :: VirtualQueryEx error %u", GetLastError( ) );
		return;
	}

	// Search downwards to find the base address
	do
	{
		*memorySize = memBasic.RegionSize;
		*baseAddress = reinterpret_cast<DWORD_PTR>( memBasic.BaseAddress );
		DWORD_PTR tempAddress = *baseAddress - 1;

		if ( ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( tempAddress ), &memBasic, sizeof( memBasic ) ) != sizeof( memBasic ) )
		{
			break;
		}
	} while ( isPageExecutable( memBasic.Protect ) );

	// Search upwards to calculate total size of executable memory
	DWORD_PTR tempAddress = *baseAddress;
	*memorySize = 0;
	do
	{
		tempAddress += memBasic.RegionSize;
		*memorySize += memBasic.RegionSize;

		if ( ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( tempAddress ), &memBasic, sizeof( memBasic ) ) != sizeof( memBasic ) )
		{
			break;
		}
	} while ( isPageExecutable( memBasic.Protect ) );
}

void IATSearch::filterIATPointersList( std::set<DWORD_PTR>& iatPointers ) {

	if ( iatPointers.size( ) <= 2 ) {
		return;
	}

	auto iter = iatPointers.begin( );
	std::advance( iter, iatPointers.size( ) / 2 ); //start in the middle, important!
	DWORD_PTR lastPointer = *iter++;

	for ( ; iter != iatPointers.end( );) {
		if ( ( *iter - lastPointer ) > 0x100 && ( !isIATPointerValid( lastPointer, false ) || !isIATPointerValid( *iter, false ) ) ) {
			iatPointers.erase( iter, iatPointers.end( ) );
			break;
		}
		lastPointer = *iter++;
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

static void adjustSizeForBigSections( DWORD* badValue )
{
	if ( *badValue > 100000000 )
	{
		*badValue = 100000000;
	}
}

static bool isSectionSizeTooBig( SIZE_T sectionSize ) {
	return ( sectionSize > 100000000 );
}

void IATSearch::getMemoryBaseAndSizeForIat( DWORD_PTR address, DWORD_PTR* baseAddress, DWORD* baseSize ) {
	MEMORY_BASIC_INFORMATION memBasic1{};
	MEMORY_BASIC_INFORMATION memBasic2{};
	MEMORY_BASIC_INFORMATION memBasic3{};

	if ( !ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( address ), &memBasic2, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
		return;
	}

	*baseAddress = reinterpret_cast<DWORD_PTR>( memBasic2.BaseAddress );
	*baseSize = static_cast<DWORD>( memBasic2.RegionSize );

	adjustSizeForBigSections( baseSize );

	// Get the neighbors
	if ( !ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( *baseAddress - 1 ), &memBasic1, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
		return;
	}
	if ( !ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( *baseAddress + memBasic2.RegionSize ), &memBasic3, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
		return;
	}

	if ( memBasic3.State != MEM_COMMIT || memBasic1.State != MEM_COMMIT || ( memBasic3.Protect & PAGE_NOACCESS ) || ( memBasic1.Protect & PAGE_NOACCESS ) ) {
		return;
	}

	if ( isSectionSizeTooBig( memBasic1.RegionSize ) || isSectionSizeTooBig( memBasic2.RegionSize ) || isSectionSizeTooBig( memBasic3.RegionSize ) ) {
		return;
	}

	DWORD_PTR start = reinterpret_cast<DWORD_PTR>( memBasic1.BaseAddress );
	DWORD_PTR end = reinterpret_cast<DWORD_PTR>( memBasic3.BaseAddress ) + memBasic3.RegionSize;

	*baseAddress = start;
	*baseSize = static_cast<DWORD>( end - start );
}
