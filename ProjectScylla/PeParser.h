#pragma once
#include <windows.h>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>

class PeSection
{
public:
	wchar_t name[ IMAGE_SIZEOF_SHORT_NAME + 1 ];
	std::uintptr_t uVirtualAddress;
	std::uint32_t uVirtualSize;
	std::uint32_t uRawAddress;
	std::uint32_t uRawSize;
	std::uint32_t uCharacteristics;

	bool isDumped;

	bool highlightVirtualSize( );
};

class PeFileSection {
public:
	IMAGE_SECTION_HEADER sectionHeader;
	std::uint8_t* pData;
	std::uint32_t uDataSize;
	std::uint32_t uNormalSize;

	PeFileSection( )
	{
		ZeroMemory( &sectionHeader, sizeof( IMAGE_SECTION_HEADER ) );
		pData = nullptr;
		uDataSize = 0;
		uNormalSize = 0;
	}
};

class PeParser
{
public:
	PeParser( );
	PeParser( const wchar_t* pFile, bool bReadSectionHeaders );
	PeParser( const std::uintptr_t uModuleBase, bool bReadSectionHeaders );
	PeParser( std::uint8_t* pData, std::size_t szData );
	//PeParser( std::uint8_t* pData );

	~PeParser( );

	bool initializeFromFile( const wchar_t* pFile, bool bReadSectionHeaders );
	bool initializeFromProcess( const std::uintptr_t uModuleBase, bool bReadSectionHeaders );
	bool initializeFromCopyData( std::uint8_t* pData, std::size_t szData );
	bool initializeWithMapping( const wchar_t* pFilePath );


	bool isValidPeFile( ) const;
	bool isPE64( ) const;
	bool isPE32( ) const;

	bool isTargetFileSamePeFormat( ) const;

	std::uint16_t getNumberOfSections( ) const;
	std::vector<PeFileSection>& getSectionHeaderList( );

	bool hasExportDirectory( );
	bool hasTLSDirectory( );
	bool hasRelocationDirectory( );
	bool hasOverlayData( );

	std::uint32_t getEntryPoint( ) const;

	bool getSectionNameUnicode( const int nSectionIndex, wchar_t* pOutput, const int outputLen );

	std::uint32_t getSectionHeaderBasedFileSize( );
	std::uint32_t getSectionHeaderBasedSizeOfImage( );

	bool readPeSectionsFromProcess( );
	bool readPeSectionsFromFile( );

	bool savePeFileToDisk( const wchar_t* pNewFile );
	void removeDosStub( );
	void alignAllSectionHeaders( );
	void fixPeHeader( );
	void setDefaultFileAlignment( );
	bool dumpProcess( std::uintptr_t uModBase, std::uintptr_t uEntryPoint, const wchar_t* dumpFilePath );
	bool dumpProcess( std::uintptr_t uModBase, std::uintptr_t uEntryPoint, const wchar_t* dumpFilePath, std::vector<PeSection>& sectionList );

	void setEntryPointVa( std::uintptr_t uEntryPoint );
	void setEntryPointRva( std::uint32_t uEntryPoint );

	static bool updatePeHeaderChecksum( const wchar_t* targetFile, std::uint32_t uFileSize );
	std::uint8_t* getSectionMemoryByIndex( int index );
	std::uint32_t getSectionMemorySizeByIndex( int index );
	int convertRVAToOffsetVectorIndex( std::uintptr_t uRVA );
	std::uintptr_t convertOffsetToRVAVector( std::uintptr_t uOffset );
	std::uintptr_t convertRVAToOffsetVector( std::uintptr_t uRVA );
	std::uintptr_t convertRVAToOffsetRelative( std::uintptr_t uRVA );
	std::uint32_t getSectionAddressRVAByIndex( int index );

	PIMAGE_NT_HEADERS getCurrentNtHeader( ) const;
	IMAGE_DATA_DIRECTORY* getDirectory( const int directoryIndex );

	bool isValidExportTable( );

	bool isApiForwarded( const std::uintptr_t RVA );

	PIMAGE_EXPORT_DIRECTORY getExportData( );

	void parseExportTable( );
	std::uint8_t* getDataPE( );
protected:
	bool getImageData( );

	static const std::uint32_t FileAlignmentConstant = 0x200;

	const wchar_t* pFileName;
	std::uintptr_t uModuleBaseAddress;


	/************************************************************************/
	/* PE FILE                                                              */
	/*                                                                      */
	/*  IMAGE_DOS_HEADER      64   0x40                                     */
	/*	IMAGE_NT_HEADERS32   248   0xF8                                     */
	/*	IMAGE_NT_HEADERS64   264  0x108                                     */
	/*	IMAGE_SECTION_HEADER  40   0x28                                     */
	/************************************************************************/

	PIMAGE_DOS_HEADER pDosHeader;
	std::uint8_t* pDosStub; //between dos header and section header
	std::uint32_t uDosStubSize;
	PIMAGE_NT_HEADERS32 pNTHeader32;
	PIMAGE_NT_HEADERS64 pNTHeader64;
	std::vector<PeFileSection> vListPeSection;
	std::uint8_t* pOverlayData;
	std::uint32_t uOverlaySize;
	/************************************************************************/

	std::unique_ptr<std::uint8_t[ ]> pHeaderMemory;

	std::vector<std::uint8_t> vImageData;
	std::uint8_t* pImageData = nullptr;
	std::size_t szImageDataSize = 0;

	LPVOID pFileMapping = nullptr;

	HANDLE hFile;
	std::uint32_t uFileSize;

	bool readPeHeaderFromData( );
	bool readPeHeaderFromFile( bool bReadSectionHeaders );
	bool readPeHeaderFromProcess( bool bReadSectionHeaders );

	bool hasDirectory( const int directoryIndex ) const;
	bool getSectionHeaders( );
	void getDosAndNtHeader( std::uint8_t* pMemory, LONG size );
	std::uint32_t calcCorrectPeHeaderSize( bool bReadSectionHeaders ) const;
	std::uint32_t getImageSize() const;
	std::uint32_t getInitialHeaderReadSize( );
	bool openFileHandle( );
	void closeFileHandle( );
	void initClass( );

	std::uint32_t isMemoryNotNull( std::uint8_t* pData, int uDataSize );
	bool openWriteFileHandle( const wchar_t* pNewFile );

	bool readPeSectionFromFile( std::uint32_t uReadOffset, PeFileSection& peFileSection );
	bool readPeSectionFromProcess( std::uintptr_t uReadOffset, PeFileSection& peFileSection );
	bool readPeSectionFromData( std::uintptr_t uOffset, PeFileSection& peFileSection );

	bool readSectionFromData( const std::uintptr_t uReadOffset, PeFileSection& peFileSection );
	bool readSectionFromFile( const std::uint32_t uReadOffset, PeFileSection& peFileSection );
	bool readSectionFrom( std::uintptr_t uReadOffset, PeFileSection& peFileSection, const bool isProcess );


	bool readMemoryData( const std::uintptr_t uOffset, std::size_t szSize, LPVOID pDataBuffer );

	std::uintptr_t getStandardImagebase( ) const;

	bool addNewLastSection( const char* pSectionName, std::uint32_t uSectionSize, std::uint8_t* pSectionData );
	std::uint32_t alignValue( std::uint32_t uBadValue, std::uint32_t uAlignTo );

	void setNumberOfSections( std::uint16_t uNumberOfSections );

	void removeIatDirectory( );
	bool getFileOverlay( );

};
