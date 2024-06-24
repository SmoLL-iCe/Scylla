
#include "ImportRebuilder.h"
#include "StringConversion.h"
#include "ScyllaConfig.hpp"
#include "Tools/Logs.h"

/*
New Scylla section contains:

1. (optional) direct imports jump table
2. (optional) new iat
3. (optional) OFT
4. Normal IAT entries

*/

bool ImportRebuilder::rebuildImportTable( const wchar_t* pNewFilePath, std::map<std::uintptr_t, ImportModuleThunk>& vModuleList )
{
	bool bResult = false;

	std::map<std::uintptr_t, ImportModuleThunk> copyModule;

	copyModule.insert( vModuleList.begin( ), vModuleList.end( ) );

	if ( isValidPeFile( ) )
	{
		if ( readPeSectionsFromFile( ) )
		{
			setDefaultFileAlignment( );

			bResult = buildNewImportTable( copyModule );

			if ( bResult )
			{
				alignAllSectionHeaders( );
				fixPeHeader( );

				if ( bNewIatInSection )
				{
					patchFileForNewIatLocation( );
				}

				if ( bBuildDirectImportsJumpTable )
				{
					patchFileForDirectImportJumpTable( );
				}

				bResult = savePeFileToDisk( pNewFilePath );
			}
		}
	}

	return bResult;
}

bool ImportRebuilder::buildNewImportTable( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList )
{
	createNewImportSection( vModuleList );

	szImportSectionIndex = vListPeSection.size( ) - 1;

	if ( bBuildDirectImportsJumpTable )
	{
		uDirectImportsJumpTableRVA = vListPeSection[ szImportSectionIndex ].sectionHeader.VirtualAddress;
		uJMPTableMemory = vListPeSection[ szImportSectionIndex ].pData;
	}

	if ( bNewIatInSection )
	{
		uNewIatBaseAddressRVA = vListPeSection[ szImportSectionIndex ].sectionHeader.VirtualAddress;

		if ( bBuildDirectImportsJumpTable )
		{
			uNewIatBaseAddressRVA += pIatReferenceScan->getSizeInBytesOfJumpTableInSection( );
		}

		changeIatBaseAddress( vModuleList );
	}

	std::uint32_t uSize = fillImportSection( vModuleList );

	if ( !uSize )
	{
		return false;
	}

	setFlagToIATSection( ( *vModuleList.begin( ) ).second.uFirstThunk );

	std::uint32_t vaImportAddress = vListPeSection[ szImportSectionIndex ].sectionHeader.VirtualAddress;

	if ( bUseOFT )
	{
		//OFT array is at the beginning of the import section
		vaImportAddress += static_cast<std::uint32_t>( szOfOFTArray );
	}
	if ( bNewIatInSection )
	{
		vaImportAddress += static_cast<std::uint32_t>( IatSize );
	}

	if ( bBuildDirectImportsJumpTable )
	{
		vaImportAddress += static_cast<std::uint32_t>( pIatReferenceScan->getSizeInBytesOfJumpTableInSection( ) );
	}

	if ( isPE32( ) )
	{
		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress = vaImportAddress;
		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size = static_cast<std::uint32_t>( szNumberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
	}
	else
	{
		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress = vaImportAddress;
		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size = static_cast<std::uint32_t>( szNumberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
	}


	return true;
}

bool ImportRebuilder::createNewImportSection( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList )
{
	char pSectionName[ IMAGE_SIZEOF_SHORT_NAME + 1 ] = { 0 };

	const wchar_t* pSectionNameW = Config::IAT_SECTION_NAME;

	calculateImportSizes( vModuleList );

	if ( wcslen( pSectionNameW ) > IMAGE_SIZEOF_SHORT_NAME )
	{
		strcpy_s( pSectionName, ".SCY" );
	}
	else
	{
		StringConversion::ToASCII( pSectionNameW, pSectionName, _countof( pSectionName ) );
	}

	if ( bNewIatInSection )
	{
		szOfImportSection += IatSize;
	}
	if ( bBuildDirectImportsJumpTable )
	{
		szOfImportSection += pIatReferenceScan->getSizeInBytesOfJumpTableInSection( );
	}

	return addNewLastSection( pSectionName, static_cast<std::uint32_t>( szOfImportSection ), 0 );
}

void ImportRebuilder::setFlagToIATSection( std::uintptr_t uIATAddress )
{
	for ( std::size_t i = 0; i < vListPeSection.size( ); i++ )
	{
		if ( ( vListPeSection[ i ].sectionHeader.VirtualAddress <= uIATAddress ) && ( ( static_cast<std::uintptr_t>( vListPeSection[ i ].sectionHeader.VirtualAddress ) + vListPeSection[ i ].sectionHeader.Misc.VirtualSize ) > uIATAddress ) )
		{
			//section must be read and writeable
			vListPeSection[ i ].sectionHeader.Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
		}
	}
}

std::uint32_t ImportRebuilder::fillImportSection( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList )
{
	std::map<std::uintptr_t, ImportModuleThunk>::iterator mapIt;
	std::map<std::uintptr_t, ImportThunk>::iterator mapIt2;

	std::size_t szStringLength = 0;
	std::uintptr_t uLastRVA = 0;

	std::uint8_t* pSectionData = vListPeSection[ szImportSectionIndex ].pData;
	std::uint32_t uOffset = 0;
	std::uint32_t uOffsetOFTArray = 0;

	/*
	New Scylla section contains:

	1. (optional) direct imports jump table
	2. (optional) new iat
	3. (optional) OFT
	4. Normal IAT entries

	*/
	if ( bBuildDirectImportsJumpTable )
	{
		uOffset += pIatReferenceScan->getSizeInBytesOfJumpTableInSection( );
		uOffsetOFTArray += pIatReferenceScan->getSizeInBytesOfJumpTableInSection( );
	}
	if ( bNewIatInSection )
	{
		uOffset += IatSize; //new iat at the beginning
		uOffsetOFTArray += IatSize;
		memset( pSectionData, 0xFF, uOffset );
	}
	if ( bUseOFT )
	{
		uOffset += static_cast<std::uint32_t>( szOfOFTArray ); //size includes null termination
	}

	pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>( reinterpret_cast<std::uintptr_t>( pSectionData ) + uOffset );

	//skip the IMAGE_IMPORT_DESCRIPTOR
	uOffset += static_cast<std::uint32_t>( szNumberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );

	for ( mapIt = vModuleList.begin( ); mapIt != vModuleList.end( ); mapIt++ )
	{
		ImportModuleThunk* pImportModuleThunk = &( ( *mapIt ).second );

		szStringLength = addImportDescriptor( pImportModuleThunk, uOffset, uOffsetOFTArray );


		LOGS_DEBUG( "fillImportSection :: importDesc.Name %X", pImportDescriptor->Name );


		uOffset += static_cast<std::uint32_t>( szStringLength ); //stringLength has null termination char

		pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( reinterpret_cast<std::uintptr_t>( pSectionData ) + uOffset );

		//pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(getMemoryPointerFromRVA(importModuleThunk->uFirstThunk));

		uLastRVA = pImportModuleThunk->uFirstThunk - sizeof( std::uintptr_t );

		for ( mapIt2 = ( *mapIt ).second.mpThunkList.begin( ); mapIt2 != ( *mapIt ).second.mpThunkList.end( ); mapIt2++ )
		{
			ImportThunk* pImportThunk = &( ( *mapIt2 ).second );

			PIMAGE_THUNK_DATA pThunk = nullptr;

			if ( bUseOFT )
			{
				pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>( reinterpret_cast<std::uintptr_t>( pSectionData ) + uOffsetOFTArray );
				uOffsetOFTArray += sizeof( std::uintptr_t ); //increase OFT array index
			}
			else
			{
				pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>( getMemoryPointerFromRVA( pImportThunk->uRVA ) );
			}

			//check wrong iat pointer
			if ( !pThunk )
			{
				LOGS_DEBUG( "fillImportSection :: Failed to get pThunk RVA: %X", pImportThunk->uRVA );

				return 0;
			}

			if ( ( uLastRVA + sizeof( std::uintptr_t ) ) != pImportThunk->uRVA )
			{
				//add additional import desc
				addSpecialImportDescriptor( pImportThunk->uRVA, uOffsetOFTArray );

				if ( bUseOFT )
				{
					pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>( reinterpret_cast<std::uintptr_t>( pSectionData ) + uOffsetOFTArray );
					uOffsetOFTArray += sizeof( std::uintptr_t ); //increase OFT array index, next pModule
				}
			}
			uLastRVA = pImportThunk->uRVA;


			LOGS_DEBUG( "fillImportSection :: importThunk %X pThunk %X pImportByName %X uOffset %X", pImportThunk, pThunk, pImportByName, uOffset );

			szStringLength = addImportToImportTable( pImportThunk, pThunk, pImportByName, uOffset );

			uOffset += static_cast<std::uint32_t>( szStringLength ); //is 0 bei import by ordinal
			pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( reinterpret_cast<std::uintptr_t>( pImportByName ) + szStringLength );
		}

		uOffsetOFTArray += sizeof( std::uintptr_t ); //increase OFT array index, next pModule
		pImportDescriptor++;
	}

	return uOffset;
}


std::size_t ImportRebuilder::addImportDescriptor( ImportModuleThunk* pImportModule, std::uint32_t uSectionOffset, std::uint32_t uSectionOffsetOFTArray )
{
	char dllName[ MAX_PATH ];

	StringConversion::ToASCII( pImportModule->pModuleName, dllName, _countof( dllName ) );
	std::size_t stringLength = strlen( dllName ) + 1;

	/*
		Warning: stringLength MUST include null termination char
	*/

	memcpy( ( vListPeSection[ szImportSectionIndex ].pData + uSectionOffset ), dllName, stringLength ); //copy pModule name to section

	pImportDescriptor->FirstThunk = static_cast<std::uint32_t>( pImportModule->uFirstThunk );
	pImportDescriptor->Name = static_cast<std::uint32_t>( convertOffsetToRVAVector(
		vListPeSection[ szImportSectionIndex ].sectionHeader.PointerToRawData + static_cast<std::uintptr_t>( uSectionOffset ) ) );

	if ( bUseOFT )
	{
		pImportDescriptor->OriginalFirstThunk = static_cast<std::uint32_t>( convertOffsetToRVAVector(
			vListPeSection[ szImportSectionIndex ].sectionHeader.PointerToRawData + static_cast<std::uintptr_t>( uSectionOffsetOFTArray ) ) );
	}

	return stringLength;
}

void ImportRebuilder::addSpecialImportDescriptor( std::uintptr_t uRvaFirstThunk, std::uint32_t uSectionOffsetOFTArray )
{
	PIMAGE_IMPORT_DESCRIPTOR oldID = pImportDescriptor;
	pImportDescriptor++;

	pImportDescriptor->FirstThunk = static_cast<std::uint32_t>( uRvaFirstThunk );
	pImportDescriptor->Name = oldID->Name;

	if ( bUseOFT )
	{
		pImportDescriptor->OriginalFirstThunk = static_cast<std::uint32_t>(
			convertOffsetToRVAVector(
				vListPeSection[ szImportSectionIndex ].sectionHeader.PointerToRawData + static_cast<std::uintptr_t>( uSectionOffsetOFTArray ) ) );
	}
}

void ImportRebuilder::calculateImportSizes( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList )
{
	std::map<std::uintptr_t, ImportModuleThunk>::iterator mapIt;
	std::map<std::uintptr_t, ImportThunk>::iterator mapIt2;
	std::uintptr_t lastRVA = 0;


	szOfImportSection = 0;
	szOfApiAndModuleNames = 0;
	szOfOFTArray = 0;

	szNumberOfImportDescriptors = vModuleList.size( ) + 1; //last is zero'd

	for ( mapIt = vModuleList.begin( ) ; mapIt != vModuleList.end( ); mapIt++ )
	{
		lastRVA = ( *mapIt ).second.uFirstThunk - sizeof( std::uintptr_t );

		szOfApiAndModuleNames += static_cast<std::uintptr_t>( wcslen( ( *mapIt ).second.pModuleName ) + 1 );

		for ( mapIt2 = ( *mapIt ).second.mpThunkList.begin( ) ; mapIt2 != ( *mapIt ).second.mpThunkList.end( ); mapIt2++ )
		{
			if ( ( lastRVA + sizeof( std::uintptr_t ) ) != ( *mapIt2 ).second.uRVA )
			{
				szNumberOfImportDescriptors++; //add additional import desc
				szOfOFTArray += sizeof( std::uintptr_t ) + sizeof( std::uintptr_t );
			}

			if ( ( *mapIt2 ).second.name[ 0 ] != '\0' )
			{
				szOfApiAndModuleNames += sizeof( std::uint16_t ); //Hint from IMAGE_IMPORT_BY_NAME
				szOfApiAndModuleNames += static_cast<std::uintptr_t>( strlen( ( *mapIt2 ).second.name ) + 1 );
			}

			//OriginalFirstThunk Array in Import Section: value
			szOfOFTArray += sizeof( std::uintptr_t );

			lastRVA = ( *mapIt2 ).second.uRVA;
		}

		//OriginalFirstThunk Array in Import Section: NULL termination
		szOfOFTArray += sizeof( std::uintptr_t );
	}

	szOfImportSection = szOfOFTArray + szOfApiAndModuleNames + ( szNumberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
}

std::size_t ImportRebuilder::addImportToImportTable( ImportThunk* pImport, PIMAGE_THUNK_DATA pThunk, PIMAGE_IMPORT_BY_NAME pImportByName, std::uint32_t uSectionOffset )
{
	std::size_t stringLength = 0;

	if ( pImport->name[ 0 ] == '\0' )
	{
		pThunk->u1.AddressOfData = ( IMAGE_ORDINAL( pImport->uOrdinal ) | IMAGE_ORDINAL_FLAG );
	}
	else
	{
		pImportByName->Hint = pImport->uHint;

		stringLength = strlen( pImport->name ) + 1;
		memcpy( pImportByName->Name, pImport->name, stringLength );

		pThunk->u1.AddressOfData = convertOffsetToRVAVector( vListPeSection[ szImportSectionIndex ].sectionHeader.PointerToRawData + static_cast<std::uintptr_t>( uSectionOffset ) );

		if ( !pThunk->u1.AddressOfData )
		{

			LOGS_DEBUG( "addImportToImportTable :: failed to get AddressOfData %X %X", vListPeSection[ szImportSectionIndex ].sectionHeader.PointerToRawData, uSectionOffset );

		}

		//next import should be nulled
		pThunk++;
		pThunk->u1.AddressOfData = 0;


		LOGS_DEBUG( "addImportToImportTable :: pThunk->u1.AddressOfData %X %X %X", pThunk->u1.AddressOfData, pThunk, vListPeSection[ szImportSectionIndex ].sectionHeader.PointerToRawData + uSectionOffset );

		stringLength += sizeof( std::uint16_t );
	}

	return stringLength;
}

std::uint8_t* ImportRebuilder::getMemoryPointerFromRVA( std::uintptr_t uRVA )
{
	int peSectionIndex = convertRVAToOffsetVectorIndex( uRVA );

	if ( peSectionIndex == -1 )
	{
		return 0;
	}

	std::uint32_t rvaPointer = ( static_cast<std::uint32_t>( uRVA ) - vListPeSection[ peSectionIndex ].sectionHeader.VirtualAddress );
	std::uint32_t minSectionSize = rvaPointer + ( sizeof( std::uintptr_t ) * 2 ); //add space for 1 IAT address

	if ( vListPeSection[ peSectionIndex ].pData == 0 || vListPeSection[ peSectionIndex ].uDataSize == 0 )
	{
		vListPeSection[ peSectionIndex ].uDataSize = minSectionSize;
		vListPeSection[ peSectionIndex ].uNormalSize = minSectionSize;
		vListPeSection[ peSectionIndex ].pData = new std::uint8_t[ vListPeSection[ peSectionIndex ].uDataSize ];

		vListPeSection[ peSectionIndex ].sectionHeader.SizeOfRawData = vListPeSection[ peSectionIndex ].uDataSize;
	}
	else if ( vListPeSection[ peSectionIndex ].uDataSize < minSectionSize )
	{
		std::uint8_t* temp = new std::uint8_t[ minSectionSize ];
		memcpy( temp, vListPeSection[ peSectionIndex ].pData, vListPeSection[ peSectionIndex ].uDataSize );
		delete[ ] vListPeSection[ peSectionIndex ].pData;

		vListPeSection[ peSectionIndex ].pData = temp;
		vListPeSection[ peSectionIndex ].uDataSize = minSectionSize;
		vListPeSection[ peSectionIndex ].uNormalSize = minSectionSize;

		vListPeSection[ peSectionIndex ].sectionHeader.SizeOfRawData = vListPeSection[ peSectionIndex ].uDataSize;
	}

	return reinterpret_cast<std::uint8_t*>( vListPeSection[ peSectionIndex ].pData + rvaPointer );
}

void ImportRebuilder::enableOFTSupport( )
{
	bUseOFT = true;
}

void ImportRebuilder::enableNewIatInSection( std::uintptr_t uIATAddress, std::uint32_t uIatSize )
{
	bNewIatInSection = true;
	IatAddress = uIATAddress;
	IatSize = uIatSize;

	pIatReferenceScan->ScanForDirectImports = false;
	pIatReferenceScan->ScanForNormalImports = true;

	pIatReferenceScan->startScan( ProcessAccessHelp::uTargetImageBase, static_cast<std::uint32_t>( ProcessAccessHelp::uTargetSizeOfImage ), IatAddress, IatSize );
}

void ImportRebuilder::patchFileForNewIatLocation( )
{
	pIatReferenceScan->patchNewIat( getStandardImagebase( ), uNewIatBaseAddressRVA, this );
}

void ImportRebuilder::changeIatBaseAddress( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList ) const
{
	std::map<std::uintptr_t, ImportModuleThunk>::iterator mapIt;
	std::map<std::uintptr_t, ImportThunk>::iterator mapIt2;

	std::uintptr_t oldIatRva = IatAddress - ProcessAccessHelp::uTargetImageBase;

	for ( mapIt = vModuleList.begin( ) ; mapIt != vModuleList.end( ); mapIt++ )
	{
		( *mapIt ).second.uFirstThunk = ( *mapIt ).second.uFirstThunk - oldIatRva + uNewIatBaseAddressRVA;

		for ( mapIt2 = ( *mapIt ).second.mpThunkList.begin( ) ; mapIt2 != ( *mapIt ).second.mpThunkList.end( ); mapIt2++ )
		{
			( *mapIt2 ).second.uRVA = ( *mapIt2 ).second.uRVA - oldIatRva + uNewIatBaseAddressRVA;
		}
	}
}

void ImportRebuilder::patchFileForDirectImportJumpTable( )
{
	pIatReferenceScan->patchDirectJumpTable( getStandardImagebase( ), uDirectImportsJumpTableRVA, this, uJMPTableMemory, ( bNewIatInSection ) ? uNewIatBaseAddressRVA : 0 );

}

