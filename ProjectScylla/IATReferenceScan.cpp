#include "IATReferenceScan.h"
#include "Architecture.h"
#include <set>
#include "Tools/Logs.h"
#include <memory>
#include <vector>

//#define DEBUG_COMMENTS


//FileLog IATReferenceScan::directImportLog( L"Scylla_direct_imports.log" );

#include <ranges>
#include "WinApi/ApiTools.h"

int IATReferenceScan::numberOfFoundDirectImports( ) {
	return static_cast<int>( vIatDirectImportList.size( ) );
}

int IATReferenceScan::numberOfFoundUniqueDirectImports( ) {
	std::set<std::uintptr_t> apiPointers;
	for ( const auto& currentRef : vIatDirectImportList ) {
		apiPointers.insert( currentRef.uTargetAddressInIat );
	}
	return static_cast<int>( apiPointers.size( ) );
}

int IATReferenceScan::numberOfDirectImportApisNotInIat( ) {

	std::set<std::uintptr_t> apiPointers;

	for ( const auto& currentRef : vIatDirectImportList ) {

		if ( currentRef.uTargetPointer == 0 ) {

			apiPointers.insert( currentRef.uTargetAddressInIat );
		}
	}
	return static_cast<int>( apiPointers.size( ) );
}

int IATReferenceScan::getSizeInBytesOfJumpTableInSection( ) {
	return numberOfFoundUniqueDirectImports( ) * 6; // For x86 and x64 the same size, FF25 00000000
}

void IATReferenceScan::startScan( std::uintptr_t uImageBase, std::uint32_t uImageSize, std::uintptr_t uIATAddress, std::uint32_t uIatSize ) {
	MEMORY_BASIC_INFORMATION memBasic {};

	IatAddressVA = uIATAddress;
	IatSize = uIatSize;
	ImageBase = uImageBase;
	ImageSize = uImageSize;

	if ( ScanForNormalImports ) {
		vIatReferenceList.clear( );
		vIatReferenceList.reserve( 200 );
	}
	if ( ScanForDirectImports ) {
		vIatDirectImportList.clear( );
		vIatDirectImportList.reserve( 50 );
	}

	std::uintptr_t section = uImageBase;
	do {
		if ( !ApiTools::VirtualQueryEx( ProcessAccessHelp::hProcess,
			reinterpret_cast<LPVOID>( section ), &memBasic, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
			LOGS_DEBUG( "VirtualQueryEx failed %d", GetLastError( ) );
			break;
		}
		else if ( ProcessAccessHelp::isPageExecutable( memBasic.Protect ) ) {
			scanMemoryPage( memBasic.BaseAddress, memBasic.RegionSize );
		}
		section += memBasic.RegionSize;
	} while ( section < ( uImageBase + uImageSize ) );
}

//void IATReferenceScan::patchNewIatBaseMemory(std::uintptr_t newIatBaseAddress)
//{
//	NewIatAddressVA = newIatBaseAddress;
//
//	for (std::vector<IATReference>::iterator iter = vIatReferenceList.begin(); iter != vIatReferenceList.end(); iter++)
//	{
//		patchReferenceInMemory(&(*iter));
//	}
//}

void IATReferenceScan::patchDirectImportsMemory( bool junkByteAfterInstruction ) {

	JunkByteAfterInstruction = junkByteAfterInstruction;

	for ( auto& currentRef : vIatDirectImportList ) {
		patchDirectImportInMemory( &currentRef );
	}
}

void IATReferenceScan::scanMemoryPage( PVOID pBaseAddress, std::size_t szRegionSize ) {

	auto pDataBuffer = std::unique_ptr<std::uint8_t[ ]>( new std::uint8_t[ szRegionSize ] {} );

	std::uint8_t* pCurrentPos = pDataBuffer.get( );

	int nCurrentSize = static_cast<int>( szRegionSize );

	std::uintptr_t uCurrentOffset = reinterpret_cast<std::uintptr_t>( pBaseAddress );

	_DecodeResult res;

	std::uint32_t uInstructionsCount = 0, uNext = 0;

	if ( !pDataBuffer )
		return;

	if ( ProcessAccessHelp::readMemoryFromProcess( reinterpret_cast<std::uintptr_t>( pBaseAddress ), szRegionSize, static_cast<LPVOID>( pDataBuffer.get( ) ) ) ) {
		while ( true ) {
			ZeroMemory( &ProcessAccessHelp::decomposerCi, sizeof( _CodeInfo ) );
			ProcessAccessHelp::decomposerCi.code = pCurrentPos;
			ProcessAccessHelp::decomposerCi.codeLen = nCurrentSize;
			ProcessAccessHelp::decomposerCi.dt = ProcessAccessHelp::dt;
			ProcessAccessHelp::decomposerCi.codeOffset = uCurrentOffset;

			uInstructionsCount = 0;

			res = distorm_decompose( &ProcessAccessHelp::decomposerCi,
				ProcessAccessHelp::decomposerResult,
				sizeof( ProcessAccessHelp::decomposerResult ) / sizeof( ProcessAccessHelp::decomposerResult[ 0 ] ), &uInstructionsCount );

			if ( res == DECRES_INPUTERR ) {
				break;
			}

			for ( std::uint32_t i = 0; i < uInstructionsCount; i++ ) {
				if ( ProcessAccessHelp::decomposerResult[ i ].flags != FLAG_NOT_DECODABLE ) {
					analyzeInstruction( &ProcessAccessHelp::decomposerResult[ i ] );
				}
			}

			if ( res == DECRES_SUCCESS ) break; // All instructions were decoded.
			else if ( uInstructionsCount == 0 ) break;

			uNext = static_cast<unsigned long>(
				ProcessAccessHelp::decomposerResult[ uInstructionsCount - 1 ].addr - ProcessAccessHelp::decomposerResult[ 0 ].addr );

			if ( ProcessAccessHelp::decomposerResult[ uInstructionsCount - 1 ].flags != FLAG_NOT_DECODABLE ) {
				uNext += ProcessAccessHelp::decomposerResult[ uInstructionsCount - 1 ].size;
			}

			pCurrentPos += uNext;
			uCurrentOffset += uNext;
			nCurrentSize -= uNext;
		}
	}
}

void IATReferenceScan::analyzeInstruction( _DInst* pInstruction )
{
	if ( ScanForNormalImports )
	{
		findNormalIatReference( pInstruction );
	}

	if ( ScanForDirectImports )
	{
		findDirectIatReferenceMov( pInstruction );

#ifndef _WIN64
		findDirectIatReferenceCallJmp( pInstruction );
		findDirectIatReferenceLea( pInstruction );
		findDirectIatReferencePush( pInstruction );
#endif
	}
}

void IATReferenceScan::findNormalIatReference( _DInst* pInstruction )
{
	_DecodedInst inst;

	IATReference currentRef { };

	if ( META_GET_FC( pInstruction->meta ) == FC_CALL || META_GET_FC( pInstruction->meta ) == FC_UNC_BRANCH )
	{
		if ( pInstruction->size >= 5 )
		{
			currentRef.type = ( META_GET_FC( pInstruction->meta ) == FC_CALL ) ? IAT_REFERENCE_PTR_CALL : IAT_REFERENCE_PTR_JMP;

			currentRef.uAddressVA = pInstruction->addr;

			currentRef.uInstructionSize = pInstruction->size;

#ifdef _WIN64
			if ( pInstruction->flags & FLAG_RIP_RELATIVE )
			{
				distorm_format( &ProcessAccessHelp::decomposerCi, pInstruction, &inst );

				LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S,
					pInstruction->addr,
					ImageBase, inst.mnemonic.p, inst.operands.p, pInstruction->ops[ 0 ].type, pInstruction->size,
					INSTRUCTION_GET_RIP_TARGET( pInstruction ) );

				if ( INSTRUCTION_GET_RIP_TARGET( pInstruction ) >= IatAddressVA && INSTRUCTION_GET_RIP_TARGET( pInstruction ) < ( IatAddressVA + IatSize ) )
				{
					currentRef.uTargetPointer = INSTRUCTION_GET_RIP_TARGET( pInstruction );

					getIatEntryAddress( &currentRef );

					//LOGS_DEBUG( "iat entry "PRINTF_DWORD_PTR_FULL_S,currentRef.uTargetAddressInIat);

					vIatReferenceList.push_back( currentRef );
				}
			}
#else

			if ( pInstruction->ops[ 0 ].type == O_DISP )
			{
				//jmp dword ptr || call dword ptr

				distorm_format( &ProcessAccessHelp::decomposerCi, pInstruction, &inst );

				LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S,
					pInstruction->addr,
					ImageBase, inst.mnemonic.p, inst.operands.p, pInstruction->ops[ 0 ].type, pInstruction->size, static_cast<std::uintptr_t>( pInstruction->disp ) );

				if ( pInstruction->disp >= IatAddressVA && pInstruction->disp < ( IatAddressVA + IatSize ) )
				{
					currentRef.uTargetPointer = static_cast<std::uintptr_t>( pInstruction->disp );

					getIatEntryAddress( &currentRef );

					//LOGS_DEBUG( "iat entry "PRINTF_DWORD_PTR_FULL_S,currentRef.uTargetAddressInIat);

					vIatReferenceList.push_back( currentRef );
				}
			}
#endif

		}
	}
}

void IATReferenceScan::getIatEntryAddress( IATReference* pRef )
{
	if ( !ProcessAccessHelp::readMemoryFromProcess( pRef->uTargetPointer, sizeof( std::uintptr_t ), &pRef->uTargetAddressInIat ) )
	{
		pRef->uTargetAddressInIat = 0;
	}
}

bool IATReferenceScan::isAddressValidImageMemory( std::uintptr_t uAddress )
{
	MEMORY_BASIC_INFORMATION memBasic = { 0 };

	if ( !ApiTools::VirtualQueryEx( ProcessAccessHelp::hProcess,
		reinterpret_cast<LPVOID>( uAddress ), &memBasic, sizeof( MEMORY_BASIC_INFORMATION ) ) )
	{
		return false;
	}

	return ( memBasic.Type == MEM_IMAGE && ProcessAccessHelp::isPageExecutable( memBasic.Protect ) );
}

void IATReferenceScan::patchReferenceInMemory( IATReference* pRef ) const {

	auto uNewIatAddressPointer = pRef->uTargetPointer - IatAddressVA + NewIatAddressRVA;

	auto uPatchBytes = static_cast<std::uint32_t>(
#ifdef _WIN64
		uNewIatAddressPointer - pRef->uAddressVA - 6
#else
		uNewIatAddressPointer
#endif
		);
	ProcessAccessHelp::writeMemoryToProcess( pRef->uAddressVA + 2, sizeof( std::uint32_t ), &uPatchBytes );
}

void IATReferenceScan::patchDirectImportInMemory( IATReference* pRef ) const {
	if ( pRef->uTargetPointer == 0 ) return;

	std::uint8_t pPatchPreBytes[ 2 ] = { 0xFF, 0x00 };
	switch ( pRef->type ) {
	case IAT_REFERENCE_DIRECT_CALL:
	pPatchPreBytes[ 1 ] = 0x15; // FF15
	break;
	case IAT_REFERENCE_DIRECT_JMP:
	pPatchPreBytes[ 1 ] = 0x25; // FF25
	break;
	default:
	return; // Unsupported type, exit the function
	}

	if ( !JunkByteAfterInstruction ) {
		pRef->uAddressVA -= 1;
	}

	ProcessAccessHelp::writeMemoryToProcess( pRef->uAddressVA, 2, pPatchPreBytes );

	auto uPatchBytes = static_cast<std::uint32_t>(
#ifdef _WIN64
		pRef->uTargetPointer - pRef->uAddressVA - 6
#else
		pRef->uTargetPointer
#endif
		);
	ProcessAccessHelp::writeMemoryToProcess( pRef->uAddressVA + 2, sizeof( std::uint32_t ), &uPatchBytes );
}

std::uintptr_t IATReferenceScan::lookUpIatForPointer( std::uintptr_t uAddr ) {

	if ( !iatBackup ) {
		iatBackup = std::unique_ptr<std::uintptr_t[ ]>( new std::uintptr_t[ IatSize / sizeof( std::uintptr_t ) + 1 ] {} );
		if ( !iatBackup ) {
			return 0;
		}
		if ( !ProcessAccessHelp::readMemoryFromProcess( IatAddressVA, IatSize, iatBackup.get( ) ) ) {
			iatBackup.reset( );
			return 0;
		}
	}

	for ( std::size_t i = 0; i < IatSize / sizeof( std::uintptr_t ); ++i ) {
		if ( iatBackup[ i ] == uAddr ) {
			return reinterpret_cast<std::uintptr_t>( &iatBackup[ i ] ) - reinterpret_cast<std::uintptr_t>( iatBackup.get( ) ) + IatAddressVA;
		}
	}

	return 0;
}

void IATReferenceScan::patchNewIat( std::uintptr_t uStdImagebase, std::uintptr_t newIatBaseAddress, PeParser* peParser ) {
	NewIatAddressRVA = newIatBaseAddress;

	for ( auto& currentRef : vIatReferenceList ) {

		std::uintptr_t uNewIatAddressPointer = ( currentRef.uTargetPointer - IatAddressVA ) + NewIatAddressRVA + uStdImagebase;

		std::uint32_t uPatchBytes = static_cast<std::uint32_t>( uNewIatAddressPointer - ( currentRef.uAddressVA - ImageBase + uStdImagebase ) - 6 );

		std::uintptr_t uPatchOffset = peParser->convertRVAToOffsetRelative( currentRef.uAddressVA - ImageBase );

		int index = peParser->convertRVAToOffsetVectorIndex( currentRef.uAddressVA - ImageBase );

		std::uint8_t* pMemory = peParser->getSectionMemoryByIndex( index );

		std::uint32_t uMemorySize = peParser->getSectionMemorySizeByIndex( index );

		if ( uMemorySize < uPatchOffset + 6 ) {
			LOGS_DEBUG( "Error - Cannot fix IAT reference RVA: " PRINTF_DWORD_PTR_FULL_S, currentRef.uAddressVA - ImageBase );
		}
		else {
			*( reinterpret_cast<std::uint32_t*>( pMemory + uPatchOffset + 2 ) ) = uPatchBytes;
		}
	}
}

void IATReferenceScan::printDirectImportLog( )
{
	LOGS_IMPORT( "------------------------------------------------------------" );
	LOGS_IMPORT( "ImageBase " PRINTF_DWORD_PTR_FULL_S " ImageSize %08X IATAddress " PRINTF_DWORD_PTR_FULL_S " IATSize 0x%X",
		ImageBase, ImageSize, IatAddressVA, IatSize );
	int count = 0;
	bool isSuspect = false;

	for ( auto& currentRef : vIatDirectImportList ) {
		auto* apiInfo = apiReader->getApiByVirtualAddress( currentRef.uTargetAddressInIat, &isSuspect );

		count++;
		std::wstring type = L"U";

		switch ( currentRef.type ) {
		case IAT_REFERENCE_DIRECT_CALL: type = L"CALL"; break;
		case IAT_REFERENCE_DIRECT_JMP: type = L"JMP"; break;
		case IAT_REFERENCE_DIRECT_MOV: type = L"MOV"; break;
		case IAT_REFERENCE_DIRECT_PUSH: type = L"PUSH"; break;
		case IAT_REFERENCE_DIRECT_LEA: type = L"LEA"; break;
		}

		LOGS_IMPORT( "%04d AddrVA " PRINTF_DWORD_PTR_FULL_S " Type %ls Value " PRINTF_DWORD_PTR_FULL_S " IatRefPointer " PRINTF_DWORD_PTR_FULL_S " Api %s %S",
			count, currentRef.uAddressVA, type.c_str( ), currentRef.uTargetAddressInIat, currentRef.uTargetPointer, apiInfo->pModule->getFilename( ), apiInfo->name );
	}

	LOGS_IMPORT( "------------------------------------------------------------" );
}

void IATReferenceScan::findDirectIatReferenceCallJmp( _DInst* pInstruction )
{
	IATReference currentRef { };

	if ( META_GET_FC( pInstruction->meta ) == FC_CALL || META_GET_FC( pInstruction->meta ) == FC_UNC_BRANCH )
	{
		if ( ( pInstruction->size >= 5 ) && ( pInstruction->ops[ 0 ].type == O_PC ) ) //CALL/JMP 0x00000000
		{
			if ( META_GET_FC( pInstruction->meta ) == FC_CALL )
			{
				currentRef.type = IAT_REFERENCE_DIRECT_CALL;
			}
			else
			{
				currentRef.type = IAT_REFERENCE_DIRECT_JMP;
			}

			currentRef.uTargetAddressInIat = static_cast<std::uintptr_t>( INSTRUCTION_GET_TARGET( pInstruction ) );

			checkMemoryRangeAndAddToList( &currentRef, pInstruction );
		}
	}
}

void IATReferenceScan::findDirectIatReferenceMov( _DInst* pInstruction )
{
	IATReference currentRef { };
	currentRef.type = IAT_REFERENCE_DIRECT_MOV;

	if ( pInstruction->opcode == I_MOV )
	{
#ifdef _WIN64
		if ( pInstruction->size >= 7 ) //MOV REGISTER, 0xFFFFFFFFFFFFFFFF
#else
		if ( pInstruction->size >= 5 ) //MOV REGISTER, 0xFFFFFFFF
#endif
		{
			if ( pInstruction->ops[ 0 ].type == O_REG && pInstruction->ops[ 1 ].type == O_IMM )
			{
				currentRef.uTargetAddressInIat = static_cast<std::uintptr_t>( pInstruction->imm.qword );

				checkMemoryRangeAndAddToList( &currentRef, pInstruction );
			}
		}
	}
}

void IATReferenceScan::findDirectIatReferencePush( _DInst* pInstruction )
{
	IATReference currentRef { };
	currentRef.type = IAT_REFERENCE_DIRECT_PUSH;

	if ( pInstruction->size >= 5 && pInstruction->opcode == I_PUSH )
	{
		currentRef.uTargetAddressInIat = static_cast<std::uintptr_t>( pInstruction->imm.qword );

		checkMemoryRangeAndAddToList( &currentRef, pInstruction );
	}
}

void IATReferenceScan::findDirectIatReferenceLea( _DInst* pInstruction ) {

	if ( pInstruction->size >= 5 && pInstruction->opcode == I_LEA ) {

		if ( pInstruction->ops[ 0 ].type == O_REG && pInstruction->ops[ 1 ].type == O_DISP ) { // LEA EDX, [0xb58bb8]

			IATReference currentRef {};
			currentRef.type = IAT_REFERENCE_DIRECT_LEA;
			currentRef.uTargetAddressInIat = static_cast<std::uintptr_t>( pInstruction->disp );

			checkMemoryRangeAndAddToList( &currentRef, pInstruction );
		}
	}
}

void IATReferenceScan::checkMemoryRangeAndAddToList( IATReference* pRef, _DInst* pInstruction ) {

	if ( pRef->uTargetAddressInIat > 0x000FFFFF && pRef->uTargetAddressInIat != static_cast<std::uintptr_t>( -1 ) ) {

		if ( pRef->uTargetAddressInIat < ImageBase || pRef->uTargetAddressInIat > ( ImageBase + ImageSize ) ) { // Outside PE image

			bool isSuspect = false;

			if ( auto uApiAddress = apiReader->getApiByVirtualAddress( pRef->uTargetAddressInIat, &isSuspect ); uApiAddress != 0 ) {

				pRef->uAddressVA = static_cast<std::uintptr_t>( pInstruction->addr );

				pRef->uInstructionSize = pInstruction->size;

				pRef->uTargetPointer = lookUpIatForPointer( pRef->uTargetAddressInIat );

				_DecodedInst inst;
				distorm_format( &ProcessAccessHelp::decomposerCi, pInstruction, &inst );
				LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S,
					pRef->uAddressVA, ImageBase, inst.mnemonic.p, inst.operands.p, pInstruction->ops[ 0 ].type, pInstruction->size, pRef->uTargetAddressInIat );

				vIatDirectImportList.push_back( *pRef );
			}
		}
	}
}

void IATReferenceScan::patchDirectJumpTableEntry( std::uintptr_t uTargetIatPointer, std::uintptr_t uStdImagebase, std::uint32_t uDirectImportsJumpTableRVA,
	PeParser* pPeParser, std::uint8_t* pJmpTableMemory, std::uint32_t uNewIatBase ) {

	for ( auto& currentRef : vIatDirectImportList ) {

		if ( currentRef.uTargetPointer == uTargetIatPointer ) {

			auto uPatchOffset = static_cast<std::uint32_t>( pPeParser->convertRVAToOffsetRelative( currentRef.uAddressVA - ImageBase ) );

			auto nIndex = pPeParser->convertRVAToOffsetVectorIndex( currentRef.uAddressVA - ImageBase );

			auto* pMemory = pPeParser->getSectionMemoryByIndex( nIndex );

			auto uMemorySize = pPeParser->getSectionMemorySizeByIndex( nIndex );

			auto uSectionRVA = pPeParser->getSectionAddressRVAByIndex( nIndex );

			if ( currentRef.type == IAT_REFERENCE_DIRECT_CALL || currentRef.type == IAT_REFERENCE_DIRECT_JMP ) {
#ifndef _WIN64
				if ( currentRef.uInstructionSize == 5 ) {
					auto uPatchBytes = uDirectImportsJumpTableRVA - ( currentRef.uAddressVA - ImageBase ) - 5;
					patchDirectImportInDump32( 1, 5, uPatchBytes, pMemory, uMemorySize, false, uPatchOffset, uSectionRVA );
		}
#endif
	}
			else if ( currentRef.type == IAT_REFERENCE_DIRECT_PUSH || currentRef.type == IAT_REFERENCE_DIRECT_MOV ) {
#ifndef _WIN64
				if ( currentRef.uInstructionSize == 5 ) { // for x86
					auto uPatchBytes = uDirectImportsJumpTableRVA + uStdImagebase;
					patchDirectImportInDump32( 1, 5, uPatchBytes, pMemory, uMemorySize, true, uPatchOffset, uSectionRVA );
}
#else
				if ( currentRef.uInstructionSize == 10 ) { // for x64
					auto patchBytes64 = uDirectImportsJumpTableRVA + uStdImagebase;
					patchDirectImportInDump64( 2, 10, patchBytes64, pMemory, uMemorySize, true, uPatchOffset, uSectionRVA );
				}
#endif
			}
			else if ( currentRef.type == IAT_REFERENCE_DIRECT_LEA ) {
#ifndef _WIN64
				if ( currentRef.uInstructionSize == 6 ) {
					auto uPatchBytes = uDirectImportsJumpTableRVA + uStdImagebase;
					patchDirectImportInDump32( 2, 6, uPatchBytes, pMemory, uMemorySize, true, uPatchOffset, uSectionRVA );
				}
#endif
			}
		}
	}
}

void IATReferenceScan::patchDirectJumpTable( std::uintptr_t uStdImagebase, std::uint32_t uDirectImportsJumpTableRVA, PeParser* peParser, std::uint8_t* pJmpTableMemory, std::uint32_t uNewIatBase ) {

	std::set<std::uintptr_t> apiPointers;

	for ( const auto& currentRef : vIatDirectImportList ) {

		apiPointers.insert( currentRef.uTargetPointer );
	}

	for ( const auto& refTargetPointer : apiPointers ) {

		std::uintptr_t uAdjustedRefTargetPointer = refTargetPointer;

		if ( uNewIatBase ) { // Create new IAT in section
			uAdjustedRefTargetPointer = ( refTargetPointer - IatAddressVA ) + uNewIatBase + ImageBase;
		}
		// Create jump table in section
		std::uintptr_t uNewIatAddressPointer = uAdjustedRefTargetPointer - ImageBase + uStdImagebase;

		std::uint32_t uPatchBytes = 0;
#ifdef _WIN64
		uPatchBytes = static_cast<std::uint32_t>( uNewIatAddressPointer - ( uDirectImportsJumpTableRVA + uStdImagebase ) - 6 );
#else
		uPatchBytes = static_cast<std::uint32_t>( uNewIatAddressPointer );
		std::uint32_t uRelocOffset = uDirectImportsJumpTableRVA + 2;
		LOGS_IMPORT( "Relocation direct imports fix: Base RVA %08X Type HIGHLOW Offset %04X RelocTableEntry %04X",
			uRelocOffset & 0xFFFFF000, uRelocOffset & 0x00000FFF, ( IMAGE_REL_BASED_HIGHLOW << 12 ) + ( uRelocOffset & 0x00000FFF ) );
#endif
		pJmpTableMemory[ 0 ] = 0xFF;
		pJmpTableMemory[ 1 ] = 0x25;

		*reinterpret_cast<std::uint32_t*>( &pJmpTableMemory[ 2 ] ) = uPatchBytes;

		patchDirectJumpTableEntry( refTargetPointer, uStdImagebase, uDirectImportsJumpTableRVA, peParser, pJmpTableMemory, uNewIatBase );

		pJmpTableMemory += 6;
		uDirectImportsJumpTableRVA += 6;
	}
}

template<typename T>
void patchDirectImportInDump( int nPatchPreFixBytes, int nInstructionSize, T uPatchBytes,
	std::uint8_t* pMemory, std::uint32_t uMemorySize, bool bGenerateReloc,
	std::uint32_t uPatchOffset, std::uint32_t uSectionRVA, std::uint32_t relocType ) {

	if ( uMemorySize < static_cast<std::uint32_t>( uPatchOffset + nInstructionSize ) ) {
		LOGS_DEBUG( "Error - Cannot fix direct import reference RVA: %X", uSectionRVA + uPatchOffset );
		return;
	}

	pMemory += uPatchOffset + nPatchPreFixBytes;

	if ( bGenerateReloc ) {

		std::uint32_t uRelocOffset = uSectionRVA + uPatchOffset + nPatchPreFixBytes;

		LOGS_IMPORT( "Relocation direct imports fix: Base RVA %08X Type %s Offset %04X RelocTableEntry %04X",
			uRelocOffset & 0xFFFFF000, ( relocType == IMAGE_REL_BASED_HIGHLOW ? "HIGHLOW" : "DIR64" ), uRelocOffset & 0x00000FFF, ( relocType << 12 ) + ( uRelocOffset & 0x00000FFF ) );
	}

	*reinterpret_cast<T*>( pMemory ) = uPatchBytes;
}

void IATReferenceScan::patchDirectImportInDump32( int nPatchPreFixBytes, int nInstructionSize, std::uint32_t uPatchBytes, std::uint8_t* pMemory, std::uint32_t uMemorySize,
	bool bGenerateReloc, std::uint32_t uPatchOffset, std::uint32_t uSectionRVA ) {
	patchDirectImportInDump( nPatchPreFixBytes, nInstructionSize, uPatchBytes, pMemory, uMemorySize, bGenerateReloc, uPatchOffset, uSectionRVA, IMAGE_REL_BASED_HIGHLOW );
}

void IATReferenceScan::patchDirectImportInDump64( int nPatchPreFixBytes, int nInstructionSize, std::uintptr_t uPatchBytes, std::uint8_t* pMemory, std::uint32_t uMemorySize,
	bool bGenerateReloc, std::uint32_t uPatchOffset, std::uint32_t uSectionRVA ) {
	patchDirectImportInDump( nPatchPreFixBytes, nInstructionSize, uPatchBytes, pMemory, uMemorySize, bGenerateReloc, uPatchOffset, uSectionRVA, IMAGE_REL_BASED_DIR64 );
}

std::uint32_t IATReferenceScan::addAdditionalApisToList( ) {

	std::set<std::uintptr_t> apiPointers;

	for ( const auto& currentRef : vIatDirectImportList ) {

		if ( currentRef.uTargetPointer == 0 ) {
			apiPointers.insert( currentRef.uTargetAddressInIat );
		}
	}

	std::uintptr_t uIatAddy = IatAddressVA + IatSize;
	std::uint32_t uNewIatSize = IatSize;

	bool isSuspect = false;

	for ( const auto& apiIter : apiPointers ) {

		for ( auto& currentRef : vIatDirectImportList ) {

			if ( currentRef.uTargetPointer == 0 && currentRef.uTargetAddressInIat == apiIter ) {

				currentRef.uTargetPointer = uIatAddy;

				auto* apiInfo = apiReader->getApiByVirtualAddress( currentRef.uTargetAddressInIat, &isSuspect );

				apiReader->addFoundApiToModuleList( uIatAddy, apiInfo, true, isSuspect );
			}
		}

		uIatAddy += sizeof( std::uintptr_t );
		uNewIatSize += sizeof( std::uintptr_t );
	}

	return uNewIatSize;
}
