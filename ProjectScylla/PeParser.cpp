
#include "PeParser.h"
#include "ProcessAccessHelp.h"
#include <algorithm>
#include <imagehlp.h>

#pragma comment(lib, "Imagehlp.lib")

#define IMAGE_FIRST_SECTION32( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

PeParser::PeParser( )
{
	initClass( );
}

PeParser::PeParser( const wchar_t* file, bool bReadSectionHeaders )
{
	initClass( );

	pFileName = file;

	if ( !pFileName )
		return;

	readPeHeaderFromFile( bReadSectionHeaders );

	if ( !bReadSectionHeaders )
		return;

	if ( !isValidPeFile( ) )
	{
		return;
	}

	getSectionHeaders( );
}

PeParser::PeParser( const std::uintptr_t uModuleBase, bool bReadSectionHeaders )
{
	initClass( );

	uModuleBaseAddress = uModuleBase;

	if ( !uModuleBaseAddress )
	{
		return;
	}

	readPeHeaderFromProcess( bReadSectionHeaders );

	if ( !bReadSectionHeaders )
	{
		return;
	}

	if ( !isValidPeFile( ) )
	{
		return;
	}

	getSectionHeaders( );
}

PeParser::~PeParser( )
{
	for ( std::size_t i = 0; i < vListPeSection.size( ); i++ )
	{
		if ( vListPeSection[ i ].pData )
		{
			delete[ ] vListPeSection[ i ].pData;
		}
	}

	vListPeSection.clear( );
}

void PeParser::initClass( )
{
	pHeaderMemory = nullptr;

	pDosHeader = nullptr;
	pDosStub = nullptr;
	uDosStubSize = 0;
	pNTHeader32 = nullptr;
	pNTHeader64 = nullptr;
	pOverlayData = nullptr;
	uOverlaySize = 0;

	pFileName = nullptr;
	uFileSize = 0;
	uModuleBaseAddress = 0;
	hFile = INVALID_HANDLE_VALUE;
}

bool PeParser::isPE64( ) const
{
	return  ( isValidPeFile( ) ) ?
		( pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ) : false;
}

bool PeParser::isPE32( ) const
{
	return  ( isValidPeFile( ) ) ?
		( pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ) : false;
}

bool PeParser::isTargetFileSamePeFormat( ) const
{
#ifdef _WIN64
	return isPE64( );
#else
	return isPE32( );
#endif
}

bool PeParser::isValidPeFile( ) const
{
	if ( !pDosHeader )
		return false;

	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return false;

	if ( !pNTHeader32 )
		return false;

	return ( pNTHeader32->Signature == IMAGE_NT_SIGNATURE );
}

bool PeParser::hasDirectory( const int directoryIndex ) const
{
	return isPE32( ) ? ( pNTHeader32->OptionalHeader.DataDirectory[ directoryIndex ].VirtualAddress != 0 ) :
		isPE64( ) ? ( pNTHeader64->OptionalHeader.DataDirectory[ directoryIndex ].VirtualAddress != 0 ) : false;
}

IMAGE_DATA_DIRECTORY* PeParser::getDirectory( const int directoryIndex )
{
	return isPE32( ) ? ( &pNTHeader32->OptionalHeader.DataDirectory[ directoryIndex ] ) :
		isPE64( ) ? ( &pNTHeader64->OptionalHeader.DataDirectory[ directoryIndex ] ) : nullptr;
}

bool PeParser::hasExportDirectory( )
{
	return hasDirectory( IMAGE_DIRECTORY_ENTRY_EXPORT );
}

bool PeParser::hasTLSDirectory( )
{
	return hasDirectory( IMAGE_DIRECTORY_ENTRY_TLS );
}

bool PeParser::hasRelocationDirectory( )
{
	return hasDirectory( IMAGE_DIRECTORY_ENTRY_BASERELOC );
}

std::uint32_t PeParser::getEntryPoint( )
{
	return isPE32( ) ? pNTHeader32->OptionalHeader.AddressOfEntryPoint :
		isPE64( ) ? pNTHeader64->OptionalHeader.AddressOfEntryPoint : 0;
}

bool PeParser::readPeHeaderFromProcess( bool bReadSectionHeaders )
{
	std::uint32_t uCorrectSize = 0;

	std::uint32_t uReadSize = getInitialHeaderReadSize( bReadSectionHeaders );

	pHeaderMemory = std::unique_ptr<std::uint8_t[ ]>( new std::uint8_t[ uReadSize ] );

	if ( !ProcessAccessHelp::readMemoryPartlyFromProcess( uModuleBaseAddress, uReadSize, pHeaderMemory.get( ) ) )
		return false;

	getDosAndNtHeader( pHeaderMemory.get( ), static_cast<LONG>( uReadSize ) );

	if ( !isValidPeFile( ) )
		return false;

	uCorrectSize = calcCorrectPeHeaderSize( bReadSectionHeaders );

	if ( uReadSize < uCorrectSize )
	{
		uReadSize = uCorrectSize;

		pHeaderMemory.reset( new std::uint8_t[ uReadSize ] );

		if ( ProcessAccessHelp::readMemoryPartlyFromProcess( uModuleBaseAddress, uReadSize, pHeaderMemory.get( ) ) )
		{
			getDosAndNtHeader( pHeaderMemory.get( ), static_cast<LONG>( uReadSize ) );
		}
	}

	return true;
}

bool PeParser::readPeHeaderFromFile( bool bReadSectionHeaders )
{
	std::uint32_t uCorrectSize = 0;
	DWORD dwNumberOfBytesRead = 0;

	std::uint32_t uReadSize = getInitialHeaderReadSize( bReadSectionHeaders );

	pHeaderMemory = std::unique_ptr<std::uint8_t[ ]>( new std::uint8_t[ uReadSize ] );

	if ( !openFileHandle( ) )
		return false;

	uFileSize = ProcessAccessHelp::getFileSize( hFile );

	if ( !ReadFile( hFile, pHeaderMemory.get( ), uReadSize, &dwNumberOfBytesRead, 0 ) )
	{
		closeFileHandle( );
		return false;
	}

	getDosAndNtHeader( pHeaderMemory.get( ), static_cast<LONG>( uReadSize ) );

	if ( !isValidPeFile( ) )
	{
		closeFileHandle( );
		return false;
	}

	uCorrectSize = calcCorrectPeHeaderSize( bReadSectionHeaders );

	if ( uReadSize < uCorrectSize )
	{
		uReadSize = uCorrectSize;

		if ( uFileSize > 0 )
		{
			if ( uFileSize < uCorrectSize )
			{
				uReadSize = uFileSize;
			}
		}

		pHeaderMemory.reset( new std::uint8_t[ uReadSize ] );

		SetFilePointer( hFile, 0, 0, FILE_BEGIN );

		if ( ReadFile( hFile, pHeaderMemory.get( ), uReadSize, &dwNumberOfBytesRead, 0 ) )
		{
			getDosAndNtHeader( pHeaderMemory.get( ), static_cast<LONG>( uReadSize ) );
		}
	}

	closeFileHandle( );

	return true;
}

bool PeParser::readPeSectionsFromProcess( )
{
	bool bResult = true;

	vListPeSection.reserve( getNumberOfSections( ) );

	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		std::uintptr_t uReadOffset = vListPeSection[ i ].sectionHeader.VirtualAddress + uModuleBaseAddress;

		vListPeSection[ i ].uNormalSize = vListPeSection[ i ].sectionHeader.Misc.VirtualSize;

		if ( !readSectionFromProcess( uReadOffset, vListPeSection[ i ] ) )
		{
			bResult = false;
		}
	}

	return bResult;
}

bool PeParser::readPeSectionsFromFile( )
{
	bool bResult = true;

	vListPeSection.reserve( getNumberOfSections( ) );

	if ( !openFileHandle( ) )
		return false;

	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		std::uint32_t uReadOffset = vListPeSection[ i ].sectionHeader.PointerToRawData;

		vListPeSection[ i ].uNormalSize = vListPeSection[ i ].sectionHeader.SizeOfRawData;

		if ( !readSectionFromFile( uReadOffset, vListPeSection[ i ] ) )
		{
			bResult = false;
		}
	}

	closeFileHandle( );

	return bResult;
}

bool PeParser::getSectionHeaders( )
{
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION( pNTHeader32 );

	PeFileSection peFileSection;

	vListPeSection.clear( );

	vListPeSection.reserve( getNumberOfSections( ) );

	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		memcpy_s( &peFileSection.sectionHeader, sizeof( IMAGE_SECTION_HEADER ), pSection, sizeof( IMAGE_SECTION_HEADER ) );

		vListPeSection.push_back( peFileSection );

		pSection++;
	}

	return true;
}

bool PeParser::getSectionNameUnicode( const int nSectionIndex, wchar_t* pOutput, const int outputLen )
{
	char sectionNameA[ IMAGE_SIZEOF_SHORT_NAME + 1 ] = { 0 };

	pOutput[ 0 ] = 0;

	memcpy( sectionNameA, vListPeSection[ nSectionIndex ].sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME ); //not null terminated

	return ( swprintf_s( pOutput, outputLen, L"%S", sectionNameA ) != -1 );
}

std::uint16_t PeParser::getNumberOfSections( ) const
{
	return pNTHeader32->FileHeader.NumberOfSections;
}

void PeParser::setNumberOfSections( std::uint16_t uNumberOfSections )
{
	pNTHeader32->FileHeader.NumberOfSections = uNumberOfSections;
}

std::vector<PeFileSection>& PeParser::getSectionHeaderList( )
{
	return vListPeSection;
}

void PeParser::getDosAndNtHeader( std::uint8_t* pMemory, LONG size )
{
	pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( pMemory );

	pNTHeader32 = nullptr;
	pNTHeader64 = nullptr;
	uDosStubSize = 0;
	pDosStub = nullptr;

	if ( pDosHeader->e_lfanew > 0 && pDosHeader->e_lfanew < size ) //malformed PE
	{
		auto headerOffset = static_cast<std::uintptr_t>( pDosHeader->e_lfanew );
		pNTHeader32 = reinterpret_cast<PIMAGE_NT_HEADERS32>( pMemory + headerOffset );
		pNTHeader64 = reinterpret_cast<PIMAGE_NT_HEADERS64>( pMemory + headerOffset );

		if ( headerOffset > sizeof( IMAGE_DOS_HEADER ) )
		{
			uDosStubSize = static_cast<std::uint32_t>( headerOffset - sizeof( IMAGE_DOS_HEADER ) );
			pDosStub = pMemory + sizeof( IMAGE_DOS_HEADER );
		}
		else if ( headerOffset < sizeof( IMAGE_DOS_HEADER ) )
		{
			//Overlapped Headers, e.g. Spack (by Bagie)
			pDosHeader->e_lfanew = sizeof( IMAGE_DOS_HEADER );
		}
	}
}


std::uint32_t PeParser::calcCorrectPeHeaderSize( bool bReadSectionHeaders ) const
{
	std::uint32_t uCorrectSize = pDosHeader->e_lfanew + 50; //extra buffer

	if ( bReadSectionHeaders )
	{
		uCorrectSize += getNumberOfSections( ) * sizeof( IMAGE_SECTION_HEADER );
	}

	if ( isPE32( ) )
	{
		uCorrectSize += sizeof( IMAGE_NT_HEADERS32 );
	}
	else if ( isPE64( ) )
	{
		uCorrectSize += sizeof( IMAGE_NT_HEADERS64 );
	}
	else
	{
		uCorrectSize = 0; //not a valid PE
	}

	return uCorrectSize;
}

std::uint32_t PeParser::getInitialHeaderReadSize( bool bReadSectionHeaders )
{
	std::uint32_t uReadSize = sizeof( IMAGE_DOS_HEADER ) + 0x300 + sizeof( IMAGE_NT_HEADERS64 );

	//if (bReadSectionHeaders)
	//{
	//	uReadSize += (10 * sizeof(IMAGE_SECTION_HEADER));
	//}

	return uReadSize;
}

std::uint32_t PeParser::getSectionHeaderBasedFileSize( )
{
	std::uint32_t uLastRawOffset = 0, uLastRawSize = 0;

	//this is needed if the sections aren't sorted by their RawOffset (e.g. Petite)
	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		if ( ( vListPeSection[ i ].sectionHeader.PointerToRawData + vListPeSection[ i ].sectionHeader.SizeOfRawData ) > ( uLastRawOffset + uLastRawSize ) )
		{
			uLastRawOffset = vListPeSection[ i ].sectionHeader.PointerToRawData;
			uLastRawSize = vListPeSection[ i ].sectionHeader.SizeOfRawData;
		}
	}

	return ( uLastRawSize + uLastRawOffset );
}

std::uint32_t PeParser::getSectionHeaderBasedSizeOfImage( )
{
	std::uint32_t uLastVirtualOffset = 0, uLastVirtualSize = 0;

	//this is needed if the sections aren't sorted by their RawOffset (e.g. Petite)
	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		if ( ( vListPeSection[ i ].sectionHeader.VirtualAddress + vListPeSection[ i ].sectionHeader.Misc.VirtualSize ) > ( uLastVirtualOffset + uLastVirtualSize ) )
		{
			uLastVirtualOffset = vListPeSection[ i ].sectionHeader.VirtualAddress;
			uLastVirtualSize = vListPeSection[ i ].sectionHeader.Misc.VirtualSize;
		}
	}

	return ( uLastVirtualSize + uLastVirtualOffset );
}

bool PeParser::openFileHandle( )
{
	if ( hFile == INVALID_HANDLE_VALUE )
	{
		hFile = ( pFileName ) ? CreateFile( pFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 ) : INVALID_HANDLE_VALUE;
	}

	return ( hFile != INVALID_HANDLE_VALUE );
}

bool PeParser::openWriteFileHandle( const wchar_t* pNewFile )
{
	hFile = ( pNewFile ) ? CreateFile( pNewFile, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 ) : INVALID_HANDLE_VALUE;

	return ( hFile != INVALID_HANDLE_VALUE );
}

void PeParser::closeFileHandle( )
{
	if ( hFile != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hFile );

		hFile = INVALID_HANDLE_VALUE;
	}
}

bool PeParser::readSectionFromProcess( const std::uintptr_t uReadOffset, PeFileSection& peFileSection )
{
	return readSectionFrom( uReadOffset, peFileSection, true ); //process
}

bool PeParser::readSectionFromFile( const std::uint32_t uReadOffset, PeFileSection& peFileSection )
{
	return readSectionFrom( uReadOffset, peFileSection, false ); //file
}

bool PeParser::readSectionFrom( const std::uintptr_t uReadOffset, PeFileSection& peFileSection, const bool isProcess )
{
	const std::uint32_t uMaxReadSize = 0x100;
	std::uint8_t pData[ uMaxReadSize ];
	bool bResult = true;

	if ( !uReadOffset || !( peFileSection.uDataSize = peFileSection.uNormalSize ) )
	{
		return true; // Section without pData is valid
	}

	if ( peFileSection.uDataSize <= uMaxReadSize )
	{
		return isProcess ? readPeSectionFromProcess( uReadOffset, peFileSection ) :
			readPeSectionFromFile( static_cast<std::uint32_t>( uReadOffset ), peFileSection );
	}

	std::uint32_t uCurrentReadSize = peFileSection.uDataSize % uMaxReadSize ? peFileSection.uDataSize % uMaxReadSize : uMaxReadSize;
	std::uintptr_t uCurrentOffset = uReadOffset + peFileSection.uDataSize - uCurrentReadSize;

	while ( uCurrentOffset >= uReadOffset ) // Start from the end
	{
		std::memset( pData, 0, uCurrentReadSize );

		bResult = isProcess ? ProcessAccessHelp::readMemoryPartlyFromProcess( uCurrentOffset, uCurrentReadSize, pData ) :
			ProcessAccessHelp::readMemoryFromFile( hFile, static_cast<LONG>( uCurrentOffset ), uCurrentReadSize, pData );

		if ( !bResult )
		{
			break;
		}

		std::uint32_t uValuesFound = isMemoryNotNull( pData, uCurrentReadSize );
		if ( uValuesFound )
		{
			uCurrentOffset += uValuesFound;
			if ( uReadOffset < uCurrentOffset )
			{
				peFileSection.uDataSize = static_cast<std::uint32_t>( uCurrentOffset - uReadOffset ) + sizeof( std::uint32_t );
				peFileSection.uDataSize = min( peFileSection.uDataSize, peFileSection.uNormalSize );
			}
			break;
		}

		uCurrentReadSize = uMaxReadSize;
		uCurrentOffset -= uCurrentReadSize;
	}

	if ( peFileSection.uDataSize )
	{
		bResult = isProcess ? readPeSectionFromProcess( uReadOffset, peFileSection ) :
			readPeSectionFromFile( static_cast<std::uint32_t>( uReadOffset ), peFileSection );
	}

	return bResult;
}


std::uint32_t PeParser::isMemoryNotNull( std::uint8_t* pData, int uDataSize )
{
	for ( int i = ( uDataSize - 1 ); i >= 0; i-- )
	{
		if ( pData[ i ] != 0 )
		{
			return i + 1;
		}
	}

	return 0;
}

bool PeParser::savePeFileToDisk( const wchar_t* pNewFile )
{
	bool bResult = true;

	if ( getNumberOfSections( ) != vListPeSection.size( ) )
	{
		return false;
	}

	if ( !openWriteFileHandle( pNewFile ) )
	{
		return false;
	}

	std::uint32_t uFileOffset = 0;
	auto writeSection = [&]( const void* pData, std::uint32_t size ) -> bool {
		if ( !ProcessAccessHelp::writeMemoryToFile( hFile, uFileOffset, size, pData ) )
		{
			bResult = false;
			return false;
		}

		uFileOffset += size;
		return true;
		};

	auto writeZero = [&]( std::uint32_t size ) -> bool {

		std::unique_ptr<std::uint8_t[ ]> pZeroData = std::make_unique<std::uint8_t[ ]>( size );

		if ( !pZeroData )
			return false;

		std::memset( pZeroData.get( ), 0, size );

		if ( !ProcessAccessHelp::writeMemoryToFile( hFile, uFileOffset, size, pZeroData.get( ) ) )
			return false;

		uFileOffset += size;

		return true;
		};


	//Dos header
	writeSection( pDosHeader, sizeof( IMAGE_DOS_HEADER ) );

	if ( uDosStubSize && pDosStub )
	{
		//Dos Stub
		writeSection( pDosStub, uDosStubSize );
	}

	//Pe Header
	writeSection( pNTHeader32, isPE32( ) ? sizeof( IMAGE_NT_HEADERS32 ) : sizeof( IMAGE_NT_HEADERS64 ) );


	//section headers
	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		writeSection( &vListPeSection[ i ].sectionHeader, sizeof( IMAGE_SECTION_HEADER ) );
	}

	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		if ( !vListPeSection[ i ].sectionHeader.PointerToRawData )
			continue;


		if ( vListPeSection[ i ].sectionHeader.PointerToRawData > uFileOffset )
		{
			writeZero( vListPeSection[ i ].sectionHeader.PointerToRawData - uFileOffset );//padding
		}

		if ( !vListPeSection[ i ].uDataSize )
			continue;

		auto uWriteSize = vListPeSection[ i ].uDataSize;

		if ( !ProcessAccessHelp::writeMemoryToFile( hFile, vListPeSection[ i ].sectionHeader.PointerToRawData, uWriteSize, vListPeSection[ i ].pData ) )
		{
			break;
		}

		uFileOffset += uWriteSize;

		if ( vListPeSection[ i ].uDataSize < vListPeSection[ i ].sectionHeader.SizeOfRawData ) //padding
		{
			uWriteSize = vListPeSection[ i ].sectionHeader.SizeOfRawData - vListPeSection[ i ].uDataSize;

			if ( !writeZero( uWriteSize ) )
			{
				break;
			}
		}

	}

	//add overlay?
	if ( uOverlaySize && pOverlayData )
	{
		writeSection( pOverlayData, uOverlaySize );
	}

	SetEndOfFile( hFile );

	closeFileHandle( );

	return bResult;
}

void PeParser::removeDosStub( )
{
	if ( pDosHeader )
	{
		uDosStubSize = 0;
		pDosStub = nullptr;
		pDosHeader->e_lfanew = sizeof( IMAGE_DOS_HEADER );
	}
}

bool PeParser::readPeSectionFromFile( std::uint32_t uReadOffset, PeFileSection& peFileSection )
{
	DWORD dwBytesRead = 0;

	peFileSection.pData = new std::uint8_t[ peFileSection.uDataSize ];

	SetFilePointer( hFile, uReadOffset, 0, FILE_BEGIN );

	return ( ReadFile( hFile, peFileSection.pData, peFileSection.uDataSize, &dwBytesRead, 0 ) != FALSE );
}

bool PeParser::readPeSectionFromProcess( std::uintptr_t uReadOffset, PeFileSection& peFileSection )
{
	peFileSection.pData = new std::uint8_t[ peFileSection.uDataSize ];

	return ProcessAccessHelp::readMemoryPartlyFromProcess( uReadOffset, peFileSection.uDataSize, peFileSection.pData );
}

std::uint32_t PeParser::alignValue( std::uint32_t uBadValue, std::uint32_t uAlignTo )
{
	return ( ( ( uBadValue + uAlignTo - 1 ) / uAlignTo ) * uAlignTo );
}

bool PeParser::addNewLastSection( const char* pSectionName, std::uint32_t uSectionSize, std::uint8_t* pSectionData )
{
	std::size_t szNameLength = strlen( pSectionName );
	std::uint32_t uFileAlignment = 0, uSectionAlignment = 0;
	PeFileSection peFileSection;

	if ( szNameLength > IMAGE_SIZEOF_SHORT_NAME )
	{
		return false;
	}

	if ( isPE32( ) )
	{
		uFileAlignment = pNTHeader32->OptionalHeader.FileAlignment;
		uSectionAlignment = pNTHeader32->OptionalHeader.SectionAlignment;
	}
	else
	{
		uFileAlignment = pNTHeader64->OptionalHeader.FileAlignment;
		uSectionAlignment = pNTHeader64->OptionalHeader.SectionAlignment;
	}

	memcpy_s( peFileSection.sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME, pSectionName, szNameLength );

	//last section doesn't need SizeOfRawData alignment
	peFileSection.sectionHeader.SizeOfRawData = uSectionSize; //alignValue(uSectionSize, uFileAlignment);
	peFileSection.sectionHeader.Misc.VirtualSize = alignValue( uSectionSize, uSectionAlignment );

	peFileSection.sectionHeader.PointerToRawData = alignValue( getSectionHeaderBasedFileSize( ), uFileAlignment );
	peFileSection.sectionHeader.VirtualAddress = alignValue( getSectionHeaderBasedSizeOfImage( ), uSectionAlignment );

	peFileSection.sectionHeader.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	peFileSection.uNormalSize = peFileSection.sectionHeader.SizeOfRawData;
	peFileSection.uDataSize = peFileSection.sectionHeader.SizeOfRawData;

	if ( pSectionData == 0 )
	{
		peFileSection.pData = new std::uint8_t[ peFileSection.sectionHeader.SizeOfRawData ];
		ZeroMemory( peFileSection.pData, peFileSection.sectionHeader.SizeOfRawData );
	}
	else
	{
		peFileSection.pData = pSectionData;
	}

	vListPeSection.push_back( peFileSection );

	setNumberOfSections( getNumberOfSections( ) + 1 );

	return true;
}

std::uintptr_t PeParser::getStandardImagebase( ) const
{
	return ( isPE32( ) ) ? pNTHeader32->OptionalHeader.ImageBase : static_cast<std::uintptr_t>( pNTHeader64->OptionalHeader.ImageBase );
}

int PeParser::convertRVAToOffsetVectorIndex( std::uintptr_t uRVA ) {
	for ( auto i = 0u; i < getNumberOfSections( ); ++i ) {
		const auto& section = vListPeSection[ i ].sectionHeader;
		if ( section.VirtualAddress <= uRVA && uRVA < static_cast<std::uintptr_t>( section.VirtualAddress ) + section.Misc.VirtualSize ) {
			return i;
		}
	}
	return -1;
}

std::uintptr_t PeParser::convertRVAToOffsetVector( std::uintptr_t uRVA ) {
	for ( const auto& section : vListPeSection ) {
		if ( section.sectionHeader.VirtualAddress <= uRVA && uRVA <
			static_cast<std::uintptr_t>( section.sectionHeader.VirtualAddress ) + section.sectionHeader.Misc.VirtualSize ) {
			return uRVA - section.sectionHeader.VirtualAddress + section.sectionHeader.PointerToRawData;
		}
	}
	return 0;
}

std::uintptr_t PeParser::convertRVAToOffsetRelative( std::uintptr_t uRVA ) {
	for ( const auto& section : vListPeSection ) {
		if ( section.sectionHeader.VirtualAddress <= uRVA && uRVA <
			static_cast<std::uintptr_t>( section.sectionHeader.VirtualAddress ) + section.sectionHeader.Misc.VirtualSize ) {
			return uRVA - section.sectionHeader.VirtualAddress;
		}
	}
	return 0;
}

std::uintptr_t PeParser::convertOffsetToRVAVector( std::uintptr_t uOffset ) {
	for ( const auto& section : vListPeSection ) {
		if ( section.sectionHeader.PointerToRawData <= uOffset && uOffset <
			static_cast<std::uintptr_t>( section.sectionHeader.PointerToRawData ) + section.sectionHeader.SizeOfRawData ) {
			return uOffset - section.sectionHeader.PointerToRawData + section.sectionHeader.VirtualAddress;
		}
	}
	return 0;
}

void PeParser::fixPeHeader( )
{
	std::uint32_t uSize = pDosHeader->e_lfanew + sizeof( std::uint32_t ) + sizeof( IMAGE_FILE_HEADER );

	if ( isPE32( ) )
	{
		//delete bound import directories
		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ].VirtualAddress = 0;
		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ].Size = 0;

		//max 16, zeroing possible garbage values
		for ( std::uint32_t i = pNTHeader32->OptionalHeader.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++ )
		{
			pNTHeader32->OptionalHeader.DataDirectory[ i ].Size = 0;
			pNTHeader32->OptionalHeader.DataDirectory[ i ].VirtualAddress = 0;
		}

		pNTHeader32->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		pNTHeader32->FileHeader.SizeOfOptionalHeader = sizeof( IMAGE_OPTIONAL_HEADER32 );

		pNTHeader32->OptionalHeader.SizeOfImage = getSectionHeaderBasedSizeOfImage( );

		if ( uModuleBaseAddress )
		{
			pNTHeader32->OptionalHeader.ImageBase = static_cast<std::uint32_t>( uModuleBaseAddress );
		}

		pNTHeader32->OptionalHeader.SizeOfHeaders = alignValue( static_cast<std::uintptr_t>( uSize ) +
			pNTHeader32->FileHeader.SizeOfOptionalHeader + ( getNumberOfSections( ) * sizeof( IMAGE_SECTION_HEADER ) ),
			pNTHeader32->OptionalHeader.FileAlignment );
	}
	else
	{
		//delete bound import directories
		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ].VirtualAddress = 0;
		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ].Size = 0;

		//max 16, zeroing possible garbage values
		for ( std::uint32_t i = pNTHeader64->OptionalHeader.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++ )
		{
			pNTHeader64->OptionalHeader.DataDirectory[ i ].Size = 0;
			pNTHeader64->OptionalHeader.DataDirectory[ i ].VirtualAddress = 0;
		}

		pNTHeader64->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		pNTHeader64->FileHeader.SizeOfOptionalHeader = sizeof( IMAGE_OPTIONAL_HEADER64 );

		pNTHeader64->OptionalHeader.SizeOfImage = getSectionHeaderBasedSizeOfImage( );

		if ( uModuleBaseAddress )
		{
			pNTHeader64->OptionalHeader.ImageBase = uModuleBaseAddress;
		}

		pNTHeader64->OptionalHeader.SizeOfHeaders = alignValue( static_cast<std::uintptr_t>( uSize ) +
			pNTHeader64->FileHeader.SizeOfOptionalHeader + ( getNumberOfSections( ) * sizeof( IMAGE_SECTION_HEADER ) ), pNTHeader64->OptionalHeader.FileAlignment );
	}

	removeIatDirectory( );
}

void PeParser::removeIatDirectory( )
{
	std::uint32_t uSearchAddress = 0;

	if ( isPE32( ) )
	{
		uSearchAddress = pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].VirtualAddress;

		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].VirtualAddress = 0;
		pNTHeader32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].Size = 0;
	}
	else
	{
		uSearchAddress = pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].VirtualAddress;

		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].VirtualAddress = 0;
		pNTHeader64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].Size = 0;
	}

	if ( uSearchAddress )
	{
		for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
		{
			if ( ( vListPeSection[ i ].sectionHeader.VirtualAddress <= uSearchAddress ) && ( ( vListPeSection[ i ].sectionHeader.VirtualAddress + vListPeSection[ i ].sectionHeader.Misc.VirtualSize ) > uSearchAddress ) )
			{
				//section must be read and writable
				vListPeSection[ i ].sectionHeader.Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
			}
		}
	}
}

void PeParser::setDefaultFileAlignment( )
{
	if ( isPE32( ) )
	{
		pNTHeader32->OptionalHeader.FileAlignment = FileAlignmentConstant;
	}
	else
	{
		pNTHeader64->OptionalHeader.FileAlignment = FileAlignmentConstant;
	}
}

static bool PeFileSectionSortByPointerToRawData( const PeFileSection& d1, const PeFileSection& d2 )
{
	return d1.sectionHeader.PointerToRawData < d2.sectionHeader.PointerToRawData;
}

static bool PeFileSectionSortByVirtualAddress( const PeFileSection& d1, const PeFileSection& d2 )
{
	return d1.sectionHeader.VirtualAddress < d2.sectionHeader.VirtualAddress;
}

void PeParser::alignAllSectionHeaders( )
{
	std::uint32_t uSectionAlignment = 0;
	std::uint32_t uFileAlignment = 0;
	std::uint32_t uNewFileSize = 0;

	if ( isPE32( ) )
	{
		uSectionAlignment = pNTHeader32->OptionalHeader.SectionAlignment;
		uFileAlignment = pNTHeader32->OptionalHeader.FileAlignment;
	}
	else
	{
		uSectionAlignment = pNTHeader64->OptionalHeader.SectionAlignment;
		uFileAlignment = pNTHeader64->OptionalHeader.FileAlignment;
	}

	std::sort( vListPeSection.begin( ), vListPeSection.end( ), PeFileSectionSortByPointerToRawData ); //sort by PointerToRawData ascending

	uNewFileSize = pDosHeader->e_lfanew + sizeof( std::uint32_t ) + sizeof( IMAGE_FILE_HEADER ) + pNTHeader32->FileHeader.SizeOfOptionalHeader + ( getNumberOfSections( ) * sizeof( IMAGE_SECTION_HEADER ) );


	for ( std::uint16_t i = 0; i < getNumberOfSections( ); i++ )
	{
		vListPeSection[ i ].sectionHeader.VirtualAddress = alignValue( vListPeSection[ i ].sectionHeader.VirtualAddress, uSectionAlignment );
		vListPeSection[ i ].sectionHeader.Misc.VirtualSize = alignValue( vListPeSection[ i ].sectionHeader.Misc.VirtualSize, uSectionAlignment );

		vListPeSection[ i ].sectionHeader.PointerToRawData = alignValue( uNewFileSize, uFileAlignment );
		vListPeSection[ i ].sectionHeader.SizeOfRawData = alignValue( vListPeSection[ i ].uDataSize, uFileAlignment );

		uNewFileSize = vListPeSection[ i ].sectionHeader.PointerToRawData + vListPeSection[ i ].sectionHeader.SizeOfRawData;
	}

	std::sort( vListPeSection.begin( ), vListPeSection.end( ), PeFileSectionSortByVirtualAddress ); //sort by VirtualAddress ascending
}

bool PeParser::dumpProcess( std::uintptr_t uModBase, std::uintptr_t uEntryPoint, const wchar_t* dumpFilePath )
{
	uModuleBaseAddress = uModBase;

	if ( readPeSectionsFromProcess( ) )
	{
		setDefaultFileAlignment( );

		setEntryPointVa( uEntryPoint );

		alignAllSectionHeaders( );

		fixPeHeader( );

		getFileOverlay( );

		return savePeFileToDisk( dumpFilePath );
	}

	return false;
}

bool PeParser::dumpProcess( std::uintptr_t uModBase, std::uintptr_t uEntryPoint, const wchar_t* dumpFilePath, std::vector<PeSection>& sectionList )
{
	if ( vListPeSection.size( ) == sectionList.size( ) )
	{
		for ( int i = ( getNumberOfSections( ) - 1 ); i >= 0; i-- )
		{
			if ( !sectionList[ i ].isDumped )
			{
				vListPeSection.erase( vListPeSection.begin( ) + i );
				setNumberOfSections( getNumberOfSections( ) - 1 );
			}
			else
			{
				vListPeSection[ i ].sectionHeader.Misc.VirtualSize = sectionList[ i ].uVirtualSize;
				vListPeSection[ i ].sectionHeader.SizeOfRawData = sectionList[ i ].uRawSize;
				vListPeSection[ i ].sectionHeader.Characteristics = sectionList[ i ].uCharacteristics;
			}
		}
	}

	return dumpProcess( uModBase, uEntryPoint, dumpFilePath );
}

void PeParser::setEntryPointVa( std::uintptr_t uEntryPoint )
{
	std::uint32_t uEntryPointRva = static_cast<std::uint32_t>( uEntryPoint - uModuleBaseAddress );

	setEntryPointRva( uEntryPointRva );
}

void PeParser::setEntryPointRva( std::uint32_t uEntryPoint )
{
	if ( isPE32( ) )
	{
		pNTHeader32->OptionalHeader.AddressOfEntryPoint = uEntryPoint;
	}
	else if ( isPE64( ) )
	{
		pNTHeader64->OptionalHeader.AddressOfEntryPoint = uEntryPoint;
	}
}

bool PeParser::getFileOverlay( )
{
	DWORD dwNumberOfBytesRead = 0;

	bool bResult = false;

	if ( !hasOverlayData( ) )
	{
		return false;
	}

	if ( openFileHandle( ) )
	{
		std::uint32_t overlayOffset = getSectionHeaderBasedFileSize( );

		std::uint32_t uFileSize = ProcessAccessHelp::getFileSize( hFile );

		uOverlaySize = uFileSize - overlayOffset;

		pOverlayData = new std::uint8_t[ uOverlaySize ];

		SetFilePointer( hFile, overlayOffset, 0, FILE_BEGIN );

		if ( ReadFile( hFile, pOverlayData, uOverlaySize, &dwNumberOfBytesRead, 0 ) )
		{
			bResult = true;
		}

		closeFileHandle( );
	}

	return bResult;
}

bool PeParser::hasOverlayData( )
{
	if ( !pFileName )
		return false;

	if ( isValidPeFile( ) )
	{
		std::uint32_t uFileSize = ProcessAccessHelp::getFileSize( pFileName );

		return ( uFileSize > getSectionHeaderBasedFileSize( ) );
	}

	return false;
}

bool PeParser::updatePeHeaderChecksum( const wchar_t* targetFile, std::uint32_t uFileSize )
{
	bool bResult = false;

	if ( !uFileSize )
		return false;

	auto clearHandles = [&]( HANDLE hFileToMap, HANDLE hMappedFile ) {
		if ( hMappedFile ) {
			CloseHandle( hMappedFile );
		}
		if ( hFileToMap ) {
			CloseHandle( hFileToMap );
		}
		};

	HANDLE hFileToMap = CreateFile( targetFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

	if ( !hFileToMap || hFileToMap == INVALID_HANDLE_VALUE )
		return false;

	HANDLE hMappedFile = CreateFileMapping( hFileToMap, 0, PAGE_READWRITE, 0, 0, 0 );

	if ( !hMappedFile || hMappedFile == INVALID_HANDLE_VALUE )
	{
		clearHandles( hFileToMap, hMappedFile );
		return false;
	}

	if ( GetLastError( ) != ERROR_ALREADY_EXISTS )
	{
		clearHandles( hFileToMap, hMappedFile );
		return false;
	}

	LPVOID pMappedDll = MapViewOfFile( hMappedFile, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

	if ( pMappedDll )
	{
		DWORD headerSum = 0;

		DWORD checkSum = 0;

		auto pNTHeader32 = reinterpret_cast<PIMAGE_NT_HEADERS32>( CheckSumMappedFile( pMappedDll, uFileSize, &headerSum, &checkSum ) );

		if ( pNTHeader32 )
		{
			if ( pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			{
				auto pNTHeader64 = reinterpret_cast<PIMAGE_NT_HEADERS64>( pNTHeader32 );
				pNTHeader64->OptionalHeader.CheckSum = checkSum;
			}
			else
			{
				pNTHeader32->OptionalHeader.CheckSum = checkSum;
			}

			bResult = true;
		}

		UnmapViewOfFile( pMappedDll );
	}


	clearHandles( hFileToMap, hMappedFile );

	return bResult;
}

std::uint8_t* PeParser::getSectionMemoryByIndex( int index )
{
	return vListPeSection[ index ].pData;
}

std::uint32_t PeParser::getSectionMemorySizeByIndex( int index )
{
	return vListPeSection[ index ].uDataSize;
}

std::uint32_t PeParser::getSectionAddressRVAByIndex( int index )
{
	return vListPeSection[ index ].sectionHeader.VirtualAddress;
}

PIMAGE_NT_HEADERS PeParser::getCurrentNtHeader( ) const
{
#ifdef _WIN64
	return pNTHeader64;
#else
	return pNTHeader32;
#endif
}