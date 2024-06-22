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
	return static_cast<int>( iatDirectImportList.size( ) );
}

int IATReferenceScan::numberOfFoundUniqueDirectImports( ) {
	std::set<DWORD_PTR> apiPointers;
	for ( const auto& ref : iatDirectImportList ) {
		apiPointers.insert( ref.targetAddressInIat );
	}
	return static_cast<int>( apiPointers.size( ) );
}

int IATReferenceScan::numberOfDirectImportApisNotInIat( ) {

	std::set<DWORD_PTR> apiPointers;

	for ( const auto& ref : iatDirectImportList ) {

		if ( ref.targetPointer == 0 ) {

			apiPointers.insert( ref.targetAddressInIat );
		}
	}
	return static_cast<int>( apiPointers.size( ) );
}

int IATReferenceScan::getSizeInBytesOfJumpTableInSection( ) {
	return numberOfFoundUniqueDirectImports( ) * 6; // For x86 and x64 the same size, FF25 00000000
}

void IATReferenceScan::startScan( DWORD_PTR imageBase, DWORD imageSize, DWORD_PTR iatAddress, DWORD iatSize ) {
	MEMORY_BASIC_INFORMATION memBasic{};

	IatAddressVA = iatAddress;
	IatSize = iatSize;
	ImageBase = imageBase;
	ImageSize = imageSize;

	if ( ScanForNormalImports ) {
		iatReferenceList.clear( );
		iatReferenceList.reserve( 200 );
	}
	if ( ScanForDirectImports ) {
		iatDirectImportList.clear( );
		iatDirectImportList.reserve( 50 );
	}

	DWORD_PTR section = imageBase;
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
	} while ( section < ( imageBase + imageSize ) );
}

//void IATReferenceScan::patchNewIatBaseMemory(DWORD_PTR newIatBaseAddress)
//{
//	NewIatAddressVA = newIatBaseAddress;
//
//	for (std::vector<IATReference>::iterator iter = iatReferenceList.begin(); iter != iatReferenceList.end(); iter++)
//	{
//		patchReferenceInMemory(&(*iter));
//	}
//}

void IATReferenceScan::patchDirectImportsMemory( bool junkByteAfterInstruction ) {

	JunkByteAfterInstruction = junkByteAfterInstruction;

	for ( auto& ref : iatDirectImportList ) {
		patchDirectImportInMemory( &ref );
	}
}

void IATReferenceScan::scanMemoryPage( PVOID BaseAddress, SIZE_T RegionSize ) {

	auto dataBuffer = std::unique_ptr<BYTE[ ]>( new BYTE[ RegionSize ]{} );

	BYTE* currentPos = dataBuffer.get( );

	int currentSize = static_cast<int>( RegionSize );

	DWORD_PTR currentOffset = reinterpret_cast<DWORD_PTR>( BaseAddress );

	_DecodeResult res;

	unsigned int instructionsCount = 0, next = 0;

	if ( !dataBuffer ) 
		return;

	if ( ProcessAccessHelp::readMemoryFromProcess( reinterpret_cast<DWORD_PTR>( BaseAddress ), RegionSize, static_cast<LPVOID>( dataBuffer.get( ) ) ) ) {
		while ( true ) {
			ZeroMemory( &ProcessAccessHelp::decomposerCi, sizeof( _CodeInfo ) );
			ProcessAccessHelp::decomposerCi.code = currentPos;
			ProcessAccessHelp::decomposerCi.codeLen = currentSize;
			ProcessAccessHelp::decomposerCi.dt = ProcessAccessHelp::dt;
			ProcessAccessHelp::decomposerCi.codeOffset = currentOffset;

			instructionsCount = 0;

			res = distorm_decompose( &ProcessAccessHelp::decomposerCi, 
				ProcessAccessHelp::decomposerResult, 
				sizeof( ProcessAccessHelp::decomposerResult ) / sizeof( ProcessAccessHelp::decomposerResult[ 0 ] ), &instructionsCount );

			if ( res == DECRES_INPUTERR ) {
				break;
			}

			for ( unsigned int i = 0; i < instructionsCount; i++ ) {
				if ( ProcessAccessHelp::decomposerResult[ i ].flags != FLAG_NOT_DECODABLE ) {
					analyzeInstruction( &ProcessAccessHelp::decomposerResult[ i ] );
				}
			}

			if ( res == DECRES_SUCCESS ) break; // All instructions were decoded.
			else if ( instructionsCount == 0 ) break;

			next = static_cast<unsigned long>( 
				ProcessAccessHelp::decomposerResult[ instructionsCount - 1 ].addr - ProcessAccessHelp::decomposerResult[ 0 ].addr );

			if ( ProcessAccessHelp::decomposerResult[ instructionsCount - 1 ].flags != FLAG_NOT_DECODABLE ) {
				next += ProcessAccessHelp::decomposerResult[ instructionsCount - 1 ].size;
			}

			currentPos += next;
			currentOffset += next;
			currentSize -= next;
		}
	}
}

void IATReferenceScan::analyzeInstruction( _DInst* instruction )
{
	if ( ScanForNormalImports )
	{
		findNormalIatReference( instruction );
	}

	if ( ScanForDirectImports )
	{
		findDirectIatReferenceMov( instruction );

#ifndef _WIN64
		findDirectIatReferenceCallJmp( instruction );
		findDirectIatReferenceLea( instruction );
		findDirectIatReferencePush( instruction );
#endif
	}
}

void IATReferenceScan::findNormalIatReference( _DInst* instruction )
{
	_DecodedInst inst;

	IATReference ref{ };

	if ( META_GET_FC( instruction->meta ) == FC_CALL || META_GET_FC( instruction->meta ) == FC_UNC_BRANCH )
	{
		if ( instruction->size >= 5 )
		{
			if ( META_GET_FC( instruction->meta ) == FC_CALL )
			{
				ref.type = IAT_REFERENCE_PTR_CALL;
			}
			else
			{
				ref.type = IAT_REFERENCE_PTR_JMP;
			}
			ref.addressVA = instruction->addr;
			ref.instructionSize = instruction->size;

#ifdef _WIN64
			if ( instruction->flags & FLAG_RIP_RELATIVE )
			{
				distorm_format( &ProcessAccessHelp::decomposerCi, instruction, &inst );

				LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, 
					instruction->addr , 
					ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[ 0 ].type, instruction->size, 
					INSTRUCTION_GET_RIP_TARGET( instruction ) );

				if ( INSTRUCTION_GET_RIP_TARGET( instruction ) >= IatAddressVA && INSTRUCTION_GET_RIP_TARGET( instruction ) < ( IatAddressVA + IatSize ) )
				{
					ref.targetPointer = INSTRUCTION_GET_RIP_TARGET( instruction );

					getIatEntryAddress( &ref );

					//LOGS_DEBUG( "iat entry "PRINTF_DWORD_PTR_FULL_S,ref.targetAddressInIat);

					iatReferenceList.push_back( ref );
				}
			}
#else

			if ( instruction->ops[ 0 ].type == O_DISP )
			{
				//jmp dword ptr || call dword ptr

				distorm_format( &ProcessAccessHelp::decomposerCi, instruction, &inst );

				LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, 
					instruction->addr, 
					ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[ 0 ].type, instruction->size, instruction->disp );

				if ( instruction->disp >= IatAddressVA && instruction->disp < ( IatAddressVA + IatSize ) )
				{
					ref.targetPointer = reinterpret_cast<DWORD_PTR>(instruction->disp);

					getIatEntryAddress( &ref );

					//LOGS_DEBUG( "iat entry "PRINTF_DWORD_PTR_FULL_S,ref.targetAddressInIat);

					iatReferenceList.push_back( ref );
				}
			}
#endif

		}
	}
}

void IATReferenceScan::getIatEntryAddress( IATReference* ref )
{
	if ( !ProcessAccessHelp::readMemoryFromProcess( ref->targetPointer, sizeof( DWORD_PTR ), &ref->targetAddressInIat ) )
	{
		ref->targetAddressInIat = 0;
	}
}

bool IATReferenceScan::isAddressValidImageMemory( DWORD_PTR address )
{
	MEMORY_BASIC_INFORMATION memBasic = { 0 };

	if ( !ApiTools::VirtualQueryEx( ProcessAccessHelp::hProcess, 
		reinterpret_cast<LPVOID>(address), &memBasic, sizeof( MEMORY_BASIC_INFORMATION ) ) )
	{
		return false;
	}

	return ( memBasic.Type == MEM_IMAGE && ProcessAccessHelp::isPageExecutable( memBasic.Protect ) );
}

void IATReferenceScan::patchReferenceInMemory( IATReference* ref ) const {

	auto newIatAddressPointer = ref->targetPointer - IatAddressVA + NewIatAddressRVA;

	auto patchBytes = static_cast<DWORD>(
#ifdef _WIN64
		newIatAddressPointer - ref->addressVA - 6
#else
		newIatAddressPointer
#endif
		);
	ProcessAccessHelp::writeMemoryToProcess( ref->addressVA + 2, sizeof( DWORD ), &patchBytes );
}

void IATReferenceScan::patchDirectImportInMemory( IATReference* ref ) const {
	if ( ref->targetPointer == 0 ) return;

	BYTE patchPreBytes[ 2 ] = { 0xFF, 0x00 };
	switch ( ref->type ) {
	case IAT_REFERENCE_DIRECT_CALL:
		patchPreBytes[ 1 ] = 0x15; // FF15
		break;
	case IAT_REFERENCE_DIRECT_JMP:
		patchPreBytes[ 1 ] = 0x25; // FF25
		break;
	default:
		return; // Unsupported type, exit the function
	}

	if ( !JunkByteAfterInstruction ) {
		ref->addressVA -= 1;
	}

	ProcessAccessHelp::writeMemoryToProcess( ref->addressVA, 2, patchPreBytes );

	auto patchBytes = static_cast<DWORD>(
#ifdef _WIN64
		ref->targetPointer - ref->addressVA - 6
#else
		ref->targetPointer
#endif
		);
	ProcessAccessHelp::writeMemoryToProcess( ref->addressVA + 2, sizeof( DWORD ), &patchBytes );
}

DWORD_PTR IATReferenceScan::lookUpIatForPointer( DWORD_PTR addr ) {

	if ( !iatBackup ) {
		iatBackup = std::unique_ptr<DWORD_PTR[ ]>( new DWORD_PTR[ IatSize / sizeof( DWORD_PTR ) + 1 ]{} );
		if ( !iatBackup ) {
			return 0;
		}
		if ( !ProcessAccessHelp::readMemoryFromProcess( IatAddressVA, IatSize, iatBackup.get( ) ) ) {
			iatBackup.reset( );
			return 0;
		}
	}

	for ( size_t i = 0; i < IatSize / sizeof( DWORD_PTR ); ++i ) {
		if ( iatBackup[ i ] == addr ) {
			return reinterpret_cast<DWORD_PTR>( &iatBackup[ i ] ) - reinterpret_cast<DWORD_PTR>( iatBackup.get( ) ) + IatAddressVA;
		}
	}

	return 0;
}

void IATReferenceScan::patchNewIat( DWORD_PTR stdImagebase, DWORD_PTR newIatBaseAddress, PeParser* peParser ) {
	NewIatAddressRVA = newIatBaseAddress;

	for ( auto& ref : iatReferenceList ) {

		DWORD_PTR newIatAddressPointer = ( ref.targetPointer - IatAddressVA ) + NewIatAddressRVA + stdImagebase;

		DWORD patchBytes = static_cast<DWORD>( newIatAddressPointer - ( ref.addressVA - ImageBase + stdImagebase ) - 6 );

		DWORD_PTR patchOffset = peParser->convertRVAToOffsetRelative( ref.addressVA - ImageBase );

		int index = peParser->convertRVAToOffsetVectorIndex( ref.addressVA - ImageBase );

		BYTE* memory = peParser->getSectionMemoryByIndex( index );

		DWORD memorySize = peParser->getSectionMemorySizeByIndex( index );

		if ( memorySize < patchOffset + 6 ) {
			LOGS_DEBUG( "Error - Cannot fix IAT reference RVA: " PRINTF_DWORD_PTR_FULL_S, ref.addressVA - ImageBase );
		}
		else {
			*( reinterpret_cast<DWORD*>( memory + patchOffset + 2 ) ) = patchBytes;
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

    for (auto& ref : iatDirectImportList) {
        auto* apiInfo = apiReader->getApiByVirtualAddress(ref.targetAddressInIat, &isSuspect);

        count++;
        std::wstring type = L"U";

        switch (ref.type) {
            case IAT_REFERENCE_DIRECT_CALL: type = L"CALL"; break;
            case IAT_REFERENCE_DIRECT_JMP: type = L"JMP"; break;
            case IAT_REFERENCE_DIRECT_MOV: type = L"MOV"; break;
            case IAT_REFERENCE_DIRECT_PUSH: type = L"PUSH"; break;
            case IAT_REFERENCE_DIRECT_LEA: type = L"LEA"; break;
        }

		LOGS_IMPORT( "%04d AddrVA " PRINTF_DWORD_PTR_FULL_S " Type %ls Value " PRINTF_DWORD_PTR_FULL_S " IatRefPointer " PRINTF_DWORD_PTR_FULL_S " Api %s %S", 
			count, ref.addressVA, type.c_str( ), ref.targetAddressInIat, ref.targetPointer, apiInfo->module->getFilename( ), apiInfo->name );
	}

	LOGS_IMPORT( "------------------------------------------------------------" );
}

void IATReferenceScan::findDirectIatReferenceCallJmp( _DInst* instruction )
{
	IATReference ref{ };

	if ( META_GET_FC( instruction->meta ) == FC_CALL || META_GET_FC( instruction->meta ) == FC_UNC_BRANCH )
	{
		if ( ( instruction->size >= 5 ) && ( instruction->ops[ 0 ].type == O_PC ) ) //CALL/JMP 0x00000000
		{
			if ( META_GET_FC( instruction->meta ) == FC_CALL )
			{
				ref.type = IAT_REFERENCE_DIRECT_CALL;
			}
			else
			{
				ref.type = IAT_REFERENCE_DIRECT_JMP;
			}

			ref.targetAddressInIat = static_cast<DWORD_PTR>( INSTRUCTION_GET_TARGET( instruction ) );

			checkMemoryRangeAndAddToList( &ref, instruction );
		}
	}
}

void IATReferenceScan::findDirectIatReferenceMov( _DInst* instruction )
{
	IATReference ref{ };
	ref.type = IAT_REFERENCE_DIRECT_MOV;

	if ( instruction->opcode == I_MOV )
	{
#ifdef _WIN64
		if ( instruction->size >= 7 ) //MOV REGISTER, 0xFFFFFFFFFFFFFFFF
#else
		if ( instruction->size >= 5 ) //MOV REGISTER, 0xFFFFFFFF
#endif
		{
			if ( instruction->ops[ 0 ].type == O_REG && instruction->ops[ 1 ].type == O_IMM )
			{
				ref.targetAddressInIat = static_cast<DWORD_PTR>( instruction->imm.qword );

				checkMemoryRangeAndAddToList( &ref, instruction );
			}
		}
	}
}

void IATReferenceScan::findDirectIatReferencePush( _DInst* instruction )
{
	IATReference ref{ };
	ref.type = IAT_REFERENCE_DIRECT_PUSH;

	if ( instruction->size >= 5 && instruction->opcode == I_PUSH )
	{
		ref.targetAddressInIat = static_cast<DWORD_PTR>( instruction->imm.qword );

		checkMemoryRangeAndAddToList( &ref, instruction );
	}
}

void IATReferenceScan::findDirectIatReferenceLea(_DInst* instruction) {

    if (instruction->size >= 5 && instruction->opcode == I_LEA) {

        if (instruction->ops[0].type == O_REG && instruction->ops[1].type == O_DISP) { // LEA EDX, [0xb58bb8]

            IATReference ref{};
            ref.type = IAT_REFERENCE_DIRECT_LEA;
            ref.targetAddressInIat = static_cast<DWORD_PTR>(instruction->disp);

            checkMemoryRangeAndAddToList(&ref, instruction);
        }
    }
}

void IATReferenceScan::checkMemoryRangeAndAddToList(IATReference* ref, _DInst* instruction) {

    if (ref->targetAddressInIat > 0x000FFFFF && ref->targetAddressInIat != static_cast<DWORD_PTR>(-1)) {

        if (ref->targetAddressInIat < ImageBase || ref->targetAddressInIat > (ImageBase + ImageSize)) { // Outside PE image

            bool isSuspect = false;

            if (auto apiAddress = apiReader->getApiByVirtualAddress(ref->targetAddressInIat, &isSuspect); apiAddress != 0) {

                ref->addressVA = static_cast<DWORD_PTR>(instruction->addr);

                ref->instructionSize = instruction->size;

                ref->targetPointer = lookUpIatForPointer(ref->targetAddressInIat);

                _DecodedInst inst;
                distorm_format(&ProcessAccessHelp::decomposerCi, instruction, &inst);
                LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL_S, 
                    ref->addressVA, ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[0].type, instruction->size, ref.targetAddressInIat );

                iatDirectImportList.push_back(*ref);
            }
        }
    }
}

void IATReferenceScan::patchDirectJumpTableEntry( DWORD_PTR targetIatPointer, DWORD_PTR stdImagebase, DWORD directImportsJumpTableRVA, PeParser* peParser, BYTE* jmpTableMemory, DWORD newIatBase ) {
	for ( auto& ref : iatDirectImportList ) {

		if ( ref.targetPointer == targetIatPointer ) {

			auto patchOffset = static_cast<DWORD>( peParser->convertRVAToOffsetRelative( ref.addressVA - ImageBase ) );

			auto index = peParser->convertRVAToOffsetVectorIndex( ref.addressVA - ImageBase );

			auto* memory = peParser->getSectionMemoryByIndex( index );

			auto memorySize = peParser->getSectionMemorySizeByIndex( index );

			auto sectionRVA = peParser->getSectionAddressRVAByIndex( index );

			if ( ref.type == IAT_REFERENCE_DIRECT_CALL || ref.type == IAT_REFERENCE_DIRECT_JMP ) {
	#ifndef _WIN64
				if ( ref.instructionSize == 5 ) {
					auto patchBytes = directImportsJumpTableRVA - ( ref.addressVA - ImageBase ) - 5;
					patchDirectImportInDump32( 1, 5, patchBytes, memory, memorySize, false, patchOffset, sectionRVA );
				}
	#endif
			}
			else if ( ref.type == IAT_REFERENCE_DIRECT_PUSH || ref.type == IAT_REFERENCE_DIRECT_MOV ) {
	#ifndef _WIN64
				if ( ref.instructionSize == 5 ) { // for x86
					auto patchBytes = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump32( 1, 5, patchBytes, memory, memorySize, true, patchOffset, sectionRVA );
				}
	#else
				if ( ref.instructionSize == 10 ) { // for x64
					auto patchBytes64 = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump64( 2, 10, patchBytes64, memory, memorySize, true, patchOffset, sectionRVA );
				}
	#endif
			}
			else if ( ref.type == IAT_REFERENCE_DIRECT_LEA ) {
	#ifndef _WIN64
				if ( ref.instructionSize == 6 ) {
					auto patchBytes = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump32( 2, 6, patchBytes, memory, memorySize, true, patchOffset, sectionRVA );
				}
	#endif
			}
		}
	}
}

void IATReferenceScan::patchDirectJumpTable(DWORD_PTR stdImagebase, DWORD directImportsJumpTableRVA, PeParser* peParser, BYTE* jmpTableMemory, DWORD newIatBase) {

    std::set<DWORD_PTR> apiPointers;

    for (const auto& ref : iatDirectImportList) {

        apiPointers.insert(ref.targetPointer);
    }

    for (const auto& refTargetPointer : apiPointers) {

        DWORD_PTR adjustedRefTargetPointer = refTargetPointer;

        if (newIatBase) { // Create new IAT in section
            adjustedRefTargetPointer = (refTargetPointer - IatAddressVA) + newIatBase + ImageBase;
        }
        // Create jump table in section
        DWORD_PTR newIatAddressPointer = adjustedRefTargetPointer - ImageBase + stdImagebase;

        DWORD patchBytes = 0;
#ifdef _WIN64
        patchBytes = static_cast<DWORD>(newIatAddressPointer - (directImportsJumpTableRVA + stdImagebase) - 6);
#else
        patchBytes = static_cast<DWORD>(newIatAddressPointer);
        DWORD relocOffset = directImportsJumpTableRVA + 2;
        LOGS_IMPORT("Relocation direct imports fix: Base RVA %08X Type HIGHLOW Offset %04X RelocTableEntry %04X", 
			relocOffset & 0xFFFFF000, relocOffset & 0x00000FFF, (IMAGE_REL_BASED_HIGHLOW << 12) + (relocOffset & 0x00000FFF));
#endif
        jmpTableMemory[0] = 0xFF;
        jmpTableMemory[1] = 0x25;

        *reinterpret_cast<DWORD*>(&jmpTableMemory[2]) = patchBytes;

        patchDirectJumpTableEntry(refTargetPointer, stdImagebase, directImportsJumpTableRVA, peParser, jmpTableMemory, newIatBase);

        jmpTableMemory += 6;
        directImportsJumpTableRVA += 6;
    }
}

template<typename T>
void patchDirectImportInDump( int patchPreFixBytes, int instructionSize, T patchBytes, BYTE* memory, DWORD memorySize, bool generateReloc, DWORD patchOffset, DWORD sectionRVA, DWORD relocType ) {
	if ( memorySize < static_cast<DWORD>( patchOffset + instructionSize ) ) {
		LOGS_DEBUG( "Error - Cannot fix direct import reference RVA: %X", sectionRVA + patchOffset );
		return;
	}

	memory += patchOffset + patchPreFixBytes;

	if ( generateReloc ) {

		DWORD relocOffset = sectionRVA + patchOffset + patchPreFixBytes;

		LOGS_IMPORT( "Relocation direct imports fix: Base RVA %08X Type %s Offset %04X RelocTableEntry %04X", 
			relocOffset & 0xFFFFF000, ( relocType == IMAGE_REL_BASED_HIGHLOW ? "HIGHLOW" : "DIR64" ), relocOffset & 0x00000FFF, ( relocType << 12 ) + ( relocOffset & 0x00000FFF ) );
	}

	*reinterpret_cast<T*>( memory ) = patchBytes;
}

void IATReferenceScan::patchDirectImportInDump32( int patchPreFixBytes, int instructionSize, DWORD patchBytes, BYTE* memory, DWORD memorySize, bool generateReloc, DWORD patchOffset, DWORD sectionRVA ) {
	patchDirectImportInDump( patchPreFixBytes, instructionSize, patchBytes, memory, memorySize, generateReloc, patchOffset, sectionRVA, IMAGE_REL_BASED_HIGHLOW );
}

void IATReferenceScan::patchDirectImportInDump64( int patchPreFixBytes, int instructionSize, DWORD_PTR patchBytes, BYTE* memory, DWORD memorySize, bool generateReloc, DWORD patchOffset, DWORD sectionRVA ) {
	patchDirectImportInDump( patchPreFixBytes, instructionSize, patchBytes, memory, memorySize, generateReloc, patchOffset, sectionRVA, IMAGE_REL_BASED_DIR64 );
}

DWORD IATReferenceScan::addAdditionalApisToList() {

    std::set<DWORD_PTR> apiPointers;

    for (const auto& ref : iatDirectImportList) {

        if (ref.targetPointer == 0) {
            apiPointers.insert(ref.targetAddressInIat);
        }
    }

    DWORD_PTR iatAddy = IatAddressVA + IatSize;
    DWORD newIatSize = IatSize;

    bool isSuspect = false;

    for (const auto& apiIter : apiPointers) {

        for (auto& ref : iatDirectImportList) {

            if (ref.targetPointer == 0 && ref.targetAddressInIat == apiIter) {

                ref.targetPointer = iatAddy;

                auto* apiInfo = apiReader->getApiByVirtualAddress(ref.targetAddressInIat, &isSuspect);

                apiReader->addFoundApiToModuleList(iatAddy, apiInfo, true, isSuspect);
            }
        }

        iatAddy += sizeof(DWORD_PTR);
        newIatSize += sizeof(DWORD_PTR);
    }

    return newIatSize;
}
