
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

bool ImportRebuilder::rebuildImportTable( const WCHAR* newFilePath, std::map<DWORD_PTR, ImportModuleThunk>& moduleList )
{
	bool retValue = false;

	std::map<DWORD_PTR, ImportModuleThunk> copyModule;

	copyModule.insert( moduleList.begin( ), moduleList.end( ) );

	if ( isValidPeFile( ) )
	{
		if ( readPeSectionsFromFile( ) )
		{
			setDefaultFileAlignment( );

			retValue = buildNewImportTable( copyModule );

			if ( retValue )
			{
				alignAllSectionHeaders( );
				fixPeHeader( );

				if ( newIatInSection )
				{
					patchFileForNewIatLocation( );
				}

				if ( BuildDirectImportsJumpTable )
				{
					patchFileForDirectImportJumpTable( );
				}

				retValue = savePeFileToDisk( newFilePath );
			}
		}
	}

	return retValue;
}

bool ImportRebuilder::buildNewImportTable( std::map<DWORD_PTR, ImportModuleThunk>& moduleList )
{
	createNewImportSection( moduleList );

	importSectionIndex = listPeSection.size( ) - 1;

	if ( BuildDirectImportsJumpTable )
	{
		directImportsJumpTableRVA = listPeSection[ importSectionIndex ].sectionHeader.VirtualAddress;
		JMPTableMemory = listPeSection[ importSectionIndex ].data;
	}

	if ( newIatInSection )
	{
		newIatBaseAddressRVA = listPeSection[ importSectionIndex ].sectionHeader.VirtualAddress;

		if ( BuildDirectImportsJumpTable )
		{
			newIatBaseAddressRVA += iatReferenceScan->getSizeInBytesOfJumpTableInSection( );
		}

		changeIatBaseAddress( moduleList );
	}

	DWORD dwSize = fillImportSection( moduleList );

	if ( !dwSize )
	{
		return false;
	}

	setFlagToIATSection( ( *moduleList.begin( ) ).second.firstThunk );

	DWORD vaImportAddress = listPeSection[ importSectionIndex ].sectionHeader.VirtualAddress;

	if ( useOFT )
	{
		//OFT array is at the beginning of the import section
		vaImportAddress += static_cast<DWORD>( sizeOfOFTArray );
	}
	if ( newIatInSection )
	{
		vaImportAddress += static_cast<DWORD>( IatSize );
	}

	if ( BuildDirectImportsJumpTable )
	{
		vaImportAddress += static_cast<DWORD>( iatReferenceScan->getSizeInBytesOfJumpTableInSection( ) );
	}

	if ( isPE32( ) )
	{
		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress = vaImportAddress;
		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size = static_cast<DWORD>( numberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
	}
	else
	{
		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress = vaImportAddress;
		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size = static_cast<DWORD>( numberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
	}


	return true;
}

bool ImportRebuilder::createNewImportSection( std::map<DWORD_PTR, ImportModuleThunk>& moduleList )
{
	char sectionName[ IMAGE_SIZEOF_SHORT_NAME + 1 ] = { 0 };

	const WCHAR* sectionNameW = Config::IAT_SECTION_NAME;

	calculateImportSizes( moduleList );

	if ( wcslen( sectionNameW ) > IMAGE_SIZEOF_SHORT_NAME )
	{
		strcpy_s( sectionName, ".SCY" );
	}
	else
	{
		StringConversion::ToASCII( sectionNameW, sectionName, _countof( sectionName ) );
	}

	if ( newIatInSection )
	{
		sizeOfImportSection += IatSize;
	}
	if ( BuildDirectImportsJumpTable )
	{
		sizeOfImportSection += iatReferenceScan->getSizeInBytesOfJumpTableInSection( );
	}

	return addNewLastSection( sectionName, static_cast<DWORD>( sizeOfImportSection ), 0 );
}

void ImportRebuilder::setFlagToIATSection( DWORD_PTR iatAddress )
{
	for ( size_t i = 0; i < listPeSection.size( ); i++ )
	{
		if ( ( listPeSection[ i ].sectionHeader.VirtualAddress <= iatAddress ) && ( ( static_cast<DWORD_PTR>( listPeSection[ i ].sectionHeader.VirtualAddress ) + listPeSection[ i ].sectionHeader.Misc.VirtualSize ) > iatAddress ) )
		{
			//section must be read and writeable
			listPeSection[ i ].sectionHeader.Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
		}
	}
}

DWORD ImportRebuilder::fillImportSection( std::map<DWORD_PTR, ImportModuleThunk>& moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator mapIt;
	std::map<DWORD_PTR, ImportThunk>::iterator mapIt2;

	size_t stringLength = 0;
	DWORD_PTR lastRVA = 0;

	BYTE* sectionData = listPeSection[ importSectionIndex ].data;
	DWORD offset = 0;
	DWORD offsetOFTArray = 0;

	/*
	New Scylla section contains:

	1. (optional) direct imports jump table
	2. (optional) new iat
	3. (optional) OFT
	4. Normal IAT entries

	*/
	if ( BuildDirectImportsJumpTable )
	{
		offset += iatReferenceScan->getSizeInBytesOfJumpTableInSection( );
		offsetOFTArray += iatReferenceScan->getSizeInBytesOfJumpTableInSection( );
	}
	if ( newIatInSection )
	{
		offset += IatSize; //new iat at the beginning
		offsetOFTArray += IatSize;
		memset( sectionData, 0xFF, offset );
	}
	if ( useOFT )
	{
		offset += static_cast<DWORD>( sizeOfOFTArray ); //size includes null termination
	}

	pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>( reinterpret_cast<DWORD_PTR>( sectionData ) + offset );

	//skip the IMAGE_IMPORT_DESCRIPTOR
	offset += static_cast<DWORD>( numberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );

	for ( mapIt = moduleList.begin( ); mapIt != moduleList.end( ); mapIt++ )
	{
		ImportModuleThunk* importModuleThunk = &( ( *mapIt ).second );

		stringLength = addImportDescriptor( importModuleThunk, offset, offsetOFTArray );


		LOGS_DEBUG( "fillImportSection :: importDesc.Name %X", pImportDescriptor->Name );


		offset += static_cast<DWORD>( stringLength ); //stringLength has null termination char

		pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( reinterpret_cast<DWORD_PTR>( sectionData ) + offset );

		//pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(getMemoryPointerFromRVA(importModuleThunk->firstThunk));

		lastRVA = importModuleThunk->firstThunk - sizeof( DWORD_PTR );

		for ( mapIt2 = ( *mapIt ).second.thunkList.begin( ); mapIt2 != ( *mapIt ).second.thunkList.end( ); mapIt2++ )
		{
			ImportThunk* importThunk = &( ( *mapIt2 ).second );

			PIMAGE_THUNK_DATA pThunk = nullptr;

			if ( useOFT )
			{
				pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>( reinterpret_cast<DWORD_PTR>( sectionData ) + offsetOFTArray );
				offsetOFTArray += sizeof( DWORD_PTR ); //increase OFT array index
			}
			else
			{
				pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>( getMemoryPointerFromRVA( importThunk->rva ) );
			}

			//check wrong iat pointer
			if ( !pThunk )
			{
				LOGS_DEBUG( "fillImportSection :: Failed to get pThunk RVA: %X", importThunk->rva );

				return 0;
			}

			if ( ( lastRVA + sizeof( DWORD_PTR ) ) != importThunk->rva )
			{
				//add additional import desc
				addSpecialImportDescriptor( importThunk->rva, offsetOFTArray );

				if ( useOFT )
				{
					pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>( reinterpret_cast<DWORD_PTR>( sectionData ) + offsetOFTArray );
					offsetOFTArray += sizeof( DWORD_PTR ); //increase OFT array index, next module
				}
			}
			lastRVA = importThunk->rva;


			LOGS_DEBUG( "fillImportSection :: importThunk %X pThunk %X pImportByName %X offset %X", importThunk, pThunk, pImportByName, offset );

			stringLength = addImportToImportTable( importThunk, pThunk, pImportByName, offset );

			offset += static_cast<DWORD>( stringLength ); //is 0 bei import by ordinal
			pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( reinterpret_cast<DWORD_PTR>( pImportByName ) + stringLength );
		}

		offsetOFTArray += sizeof( DWORD_PTR ); //increase OFT array index, next module
		pImportDescriptor++;
	}

	return offset;
}


size_t ImportRebuilder::addImportDescriptor( ImportModuleThunk* pImportModule, DWORD sectionOffset, DWORD sectionOffsetOFTArray )
{
	char dllName[ MAX_PATH ];

	StringConversion::ToASCII( pImportModule->moduleName, dllName, _countof( dllName ) );
	size_t stringLength = strlen( dllName ) + 1;

	/*
		Warning: stringLength MUST include null termination char
	*/

	memcpy( ( listPeSection[ importSectionIndex ].data + sectionOffset ), dllName, stringLength ); //copy module name to section

	pImportDescriptor->FirstThunk = static_cast<DWORD>( pImportModule->firstThunk );
	pImportDescriptor->Name = static_cast<DWORD>( convertOffsetToRVAVector( 
		listPeSection[ importSectionIndex ].sectionHeader.PointerToRawData + static_cast<DWORD_PTR>( sectionOffset ) ) );

	if ( useOFT )
	{
		pImportDescriptor->OriginalFirstThunk = static_cast<DWORD>( convertOffsetToRVAVector( 
			listPeSection[ importSectionIndex ].sectionHeader.PointerToRawData + static_cast<DWORD_PTR>( sectionOffsetOFTArray ) ) );
	}

	return stringLength;
}

void ImportRebuilder::addSpecialImportDescriptor( DWORD_PTR rvaFirstThunk, DWORD sectionOffsetOFTArray )
{
	PIMAGE_IMPORT_DESCRIPTOR oldID = pImportDescriptor;
	pImportDescriptor++;

	pImportDescriptor->FirstThunk = static_cast<DWORD>( rvaFirstThunk );
	pImportDescriptor->Name = oldID->Name;

	if ( useOFT )
	{
		pImportDescriptor->OriginalFirstThunk = static_cast<DWORD>( 
			convertOffsetToRVAVector( 
				listPeSection[ importSectionIndex ].sectionHeader.PointerToRawData + static_cast<DWORD_PTR>( sectionOffsetOFTArray ) ) );
	}
}

void ImportRebuilder::calculateImportSizes( std::map<DWORD_PTR, ImportModuleThunk>& moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator mapIt;
	std::map<DWORD_PTR, ImportThunk>::iterator mapIt2;
	DWORD_PTR lastRVA = 0;


	sizeOfImportSection = 0;
	sizeOfApiAndModuleNames = 0;
	sizeOfOFTArray = 0;

	numberOfImportDescriptors = moduleList.size( ) + 1; //last is zero'd

	for ( mapIt = moduleList.begin( ) ; mapIt != moduleList.end( ); mapIt++ )
	{
		lastRVA = ( *mapIt ).second.firstThunk - sizeof( DWORD_PTR );

		sizeOfApiAndModuleNames += static_cast<DWORD_PTR>( wcslen( ( *mapIt ).second.moduleName ) + 1 );

		for ( mapIt2 = ( *mapIt ).second.thunkList.begin( ) ; mapIt2 != ( *mapIt ).second.thunkList.end( ); mapIt2++ )
		{
			if ( ( lastRVA + sizeof( DWORD_PTR ) ) != ( *mapIt2 ).second.rva )
			{
				numberOfImportDescriptors++; //add additional import desc
				sizeOfOFTArray += sizeof( DWORD_PTR ) + sizeof( DWORD_PTR );
			}

			if ( ( *mapIt2 ).second.name[ 0 ] != '\0' )
			{
				sizeOfApiAndModuleNames += sizeof( WORD ); //Hint from IMAGE_IMPORT_BY_NAME
				sizeOfApiAndModuleNames += static_cast<DWORD_PTR>( strlen( ( *mapIt2 ).second.name ) + 1 );
			}

			//OriginalFirstThunk Array in Import Section: value
			sizeOfOFTArray += sizeof( DWORD_PTR );

			lastRVA = ( *mapIt2 ).second.rva;
		}

		//OriginalFirstThunk Array in Import Section: NULL termination
		sizeOfOFTArray += sizeof( DWORD_PTR );
	}

	sizeOfImportSection = sizeOfOFTArray + sizeOfApiAndModuleNames + ( numberOfImportDescriptors * sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
}

size_t ImportRebuilder::addImportToImportTable( ImportThunk* pImport, PIMAGE_THUNK_DATA pThunk, PIMAGE_IMPORT_BY_NAME pImportByName, DWORD sectionOffset )
{
	size_t stringLength = 0;

	if ( pImport->name[ 0 ] == '\0' )
	{
		pThunk->u1.AddressOfData = ( IMAGE_ORDINAL( pImport->ordinal ) | IMAGE_ORDINAL_FLAG );
	}
	else
	{
		pImportByName->Hint = pImport->hint;

		stringLength = strlen( pImport->name ) + 1;
		memcpy( pImportByName->Name, pImport->name, stringLength );

		pThunk->u1.AddressOfData = convertOffsetToRVAVector( listPeSection[ importSectionIndex ].sectionHeader.PointerToRawData + static_cast<DWORD_PTR>( sectionOffset ) );

		if ( !pThunk->u1.AddressOfData )
		{

			LOGS_DEBUG( "addImportToImportTable :: failed to get AddressOfData %X %X", listPeSection[ importSectionIndex ].sectionHeader.PointerToRawData, sectionOffset );

		}

		//next import should be nulled
		pThunk++;
		pThunk->u1.AddressOfData = 0;


		LOGS_DEBUG( "addImportToImportTable :: pThunk->u1.AddressOfData %X %X %X", pThunk->u1.AddressOfData, pThunk, listPeSection[ importSectionIndex ].sectionHeader.PointerToRawData + sectionOffset );

		stringLength += sizeof( WORD );
	}

	return stringLength;
}

BYTE* ImportRebuilder::getMemoryPointerFromRVA( DWORD_PTR dwRVA )
{
	int peSectionIndex = convertRVAToOffsetVectorIndex( dwRVA );

	if ( peSectionIndex == -1 )
	{
		return 0;
	}

	DWORD rvaPointer = ( static_cast<DWORD>( dwRVA ) - listPeSection[ peSectionIndex ].sectionHeader.VirtualAddress );
	DWORD minSectionSize = rvaPointer + ( sizeof( DWORD_PTR ) * 2 ); //add space for 1 IAT address

	if ( listPeSection[ peSectionIndex ].data == 0 || listPeSection[ peSectionIndex ].dataSize == 0 )
	{
		listPeSection[ peSectionIndex ].dataSize = minSectionSize;
		listPeSection[ peSectionIndex ].normalSize = minSectionSize;
		listPeSection[ peSectionIndex ].data = new BYTE[ listPeSection[ peSectionIndex ].dataSize ];

		listPeSection[ peSectionIndex ].sectionHeader.SizeOfRawData = listPeSection[ peSectionIndex ].dataSize;
	}
	else if ( listPeSection[ peSectionIndex ].dataSize < minSectionSize )
	{
		BYTE* temp = new BYTE[ minSectionSize ];
		memcpy( temp, listPeSection[ peSectionIndex ].data, listPeSection[ peSectionIndex ].dataSize );
		delete[ ] listPeSection[ peSectionIndex ].data;

		listPeSection[ peSectionIndex ].data = temp;
		listPeSection[ peSectionIndex ].dataSize = minSectionSize;
		listPeSection[ peSectionIndex ].normalSize = minSectionSize;

		listPeSection[ peSectionIndex ].sectionHeader.SizeOfRawData = listPeSection[ peSectionIndex ].dataSize;
	}

	return reinterpret_cast<BYTE*>( listPeSection[ peSectionIndex ].data + rvaPointer );
}

void ImportRebuilder::enableOFTSupport( )
{
	useOFT = true;
}

void ImportRebuilder::enableNewIatInSection( DWORD_PTR iatAddress, DWORD iatSize )
{
	newIatInSection = true;
	IatAddress = iatAddress;
	IatSize = iatSize;

	iatReferenceScan->ScanForDirectImports = false;
	iatReferenceScan->ScanForNormalImports = true;

	iatReferenceScan->startScan( ProcessAccessHelp::targetImageBase, static_cast<DWORD>( ProcessAccessHelp::targetSizeOfImage ), IatAddress, IatSize );
}

void ImportRebuilder::patchFileForNewIatLocation( )
{
	iatReferenceScan->patchNewIat( getStandardImagebase( ), newIatBaseAddressRVA, this );
}

void ImportRebuilder::changeIatBaseAddress( std::map<DWORD_PTR, ImportModuleThunk>& moduleList ) const
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator mapIt;
	std::map<DWORD_PTR, ImportThunk>::iterator mapIt2;

	DWORD_PTR oldIatRva = IatAddress - ProcessAccessHelp::targetImageBase;

	for ( mapIt = moduleList.begin( ) ; mapIt != moduleList.end( ); mapIt++ )
	{
		( *mapIt ).second.firstThunk = ( *mapIt ).second.firstThunk - oldIatRva + newIatBaseAddressRVA;

		for ( mapIt2 = ( *mapIt ).second.thunkList.begin( ) ; mapIt2 != ( *mapIt ).second.thunkList.end( ); mapIt2++ )
		{
			( *mapIt2 ).second.rva = ( *mapIt2 ).second.rva - oldIatRva + newIatBaseAddressRVA;
		}
	}
}

void ImportRebuilder::patchFileForDirectImportJumpTable( )
{
	iatReferenceScan->patchDirectJumpTable( getStandardImagebase( ), directImportsJumpTableRVA, this, JMPTableMemory, (newIatInSection) ? newIatBaseAddressRVA : 0 );

}

