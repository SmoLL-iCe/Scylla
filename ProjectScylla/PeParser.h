#pragma once
#include <windows.h>
#include <vector>
#include <memory>

class PeSection
{
public:
	WCHAR name[ IMAGE_SIZEOF_SHORT_NAME + 1 ];
	DWORD_PTR virtualAddress;
	DWORD  virtualSize;
	DWORD  rawAddress;
	DWORD  rawSize;
	DWORD characteristics;

	bool isDumped;

	bool highlightVirtualSize( );
};

class PeFileSection {
public:
	IMAGE_SECTION_HEADER sectionHeader;
	BYTE * data;
	DWORD dataSize;
	DWORD normalSize;

	PeFileSection()
	{
		ZeroMemory(&sectionHeader, sizeof(IMAGE_SECTION_HEADER));
		data = 0;
		dataSize = 0;
		normalSize = 0;
	}
};

class PeParser
{
public:
	PeParser(const WCHAR * file, bool readSectionHeaders = true);
	PeParser(const DWORD_PTR moduleBase, bool readSectionHeaders = true);

	~PeParser();

	bool isValidPeFile() const;
	bool isPE64() const;
	bool isPE32() const;

	bool isTargetFileSamePeFormat() const;

	WORD getNumberOfSections() const;
	std::vector<PeFileSection> & getSectionHeaderList();

	bool hasExportDirectory();
	bool hasTLSDirectory();
	bool hasRelocationDirectory();
	bool hasOverlayData();

	DWORD getEntryPoint();

	bool getSectionNameUnicode(const int sectionIndex, WCHAR * output, const int outputLen);

	DWORD getSectionHeaderBasedFileSize();
	DWORD getSectionHeaderBasedSizeOfImage();

	bool readPeSectionsFromProcess();
	bool readPeSectionsFromFile();
	bool savePeFileToDisk(const WCHAR * newFile);
	void removeDosStub();
	void alignAllSectionHeaders();
	void fixPeHeader();
	void setDefaultFileAlignment();
	bool dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, const WCHAR * dumpFilePath);
	bool dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, const WCHAR * dumpFilePath, std::vector<PeSection> & sectionList);

	void setEntryPointVa(DWORD_PTR entryPoint);
	void setEntryPointRva(DWORD entryPoint);

	static bool updatePeHeaderChecksum(const WCHAR * targetFile, DWORD fileSize);
	BYTE * getSectionMemoryByIndex(int index);
	DWORD getSectionMemorySizeByIndex(int index);
	int convertRVAToOffsetVectorIndex(DWORD_PTR dwRVA);
	DWORD_PTR convertOffsetToRVAVector(DWORD_PTR dwOffset);
	DWORD_PTR convertRVAToOffsetVector(DWORD_PTR dwRVA);
	DWORD_PTR convertRVAToOffsetRelative(DWORD_PTR dwRVA);
	DWORD getSectionAddressRVAByIndex( int index );

    PIMAGE_NT_HEADERS getCurrentNtHeader() const;
	IMAGE_DATA_DIRECTORY* getDirectory( const int directoryIndex );
protected:
	PeParser();


	static const DWORD FileAlignmentConstant = 0x200;

	const WCHAR * filename;
	DWORD_PTR moduleBaseAddress;

	/************************************************************************/
	/* PE FILE                                                              */
	/*                                                                      */
	/*  IMAGE_DOS_HEADER      64   0x40                                     */
	/*	IMAGE_NT_HEADERS32   248   0xF8                                     */
	/*	IMAGE_NT_HEADERS64   264  0x108                                     */
	/*	IMAGE_SECTION_HEADER  40   0x28                                     */
	/************************************************************************/

	PIMAGE_DOS_HEADER pDosHeader;
	BYTE * pDosStub; //between dos header and section header
	DWORD dosStubSize;
	PIMAGE_NT_HEADERS32 pNTHeader32;
	PIMAGE_NT_HEADERS64 pNTHeader64;
	std::vector<PeFileSection> listPeSection;
	BYTE * overlayData;
	DWORD overlaySize;
	/************************************************************************/

	std::unique_ptr<BYTE[]> fileMemory;
	std::unique_ptr<BYTE[ ]> headerMemory;

	HANDLE hFile;
	DWORD fileSize;

	bool readPeHeaderFromFile(bool readSectionHeaders);
	bool readPeHeaderFromProcess(bool readSectionHeaders);

	bool hasDirectory(const int directoryIndex) const;
	bool getSectionHeaders();
	void getDosAndNtHeader(BYTE * memory, LONG size);
	DWORD calcCorrectPeHeaderSize( bool readSectionHeaders ) const;
	DWORD getInitialHeaderReadSize( bool readSectionHeaders );
	bool openFileHandle();
	void closeFileHandle();
	void initClass();
	
	DWORD isMemoryNotNull( BYTE * data, int dataSize );
	bool openWriteFileHandle( const WCHAR * newFile );

	bool readPeSectionFromFile( DWORD readOffset, PeFileSection & peFileSection );
	bool readPeSectionFromProcess( DWORD_PTR readOffset, PeFileSection & peFileSection );

	bool readSectionFromProcess(const DWORD_PTR readOffset, PeFileSection & peFileSection );
	bool readSectionFromFile(const DWORD readOffset, PeFileSection & peFileSection );
	bool readSectionFrom(const DWORD_PTR readOffset, PeFileSection & peFileSection, const bool isProcess);

	
	DWORD_PTR getStandardImagebase();

	bool addNewLastSection(const CHAR * sectionName, DWORD sectionSize, BYTE * sectionData);
	DWORD alignValue(DWORD badValue, DWORD alignTo);

	void setNumberOfSections(WORD numberOfSections);
	
	void removeIatDirectory();
	bool getFileOverlay();
	
};

