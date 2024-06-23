#pragma once

#include <map>
#include <cstdint>
#include "PeParser.h"
#include "Thunks.h"
#include "IATReferenceScan.h"


class ImportRebuilder : public PeParser {
public:
	ImportRebuilder( const wchar_t* file ): PeParser( file, true )
	{
		pImportDescriptor = nullptr;
		pThunkData = nullptr;
		pImportByName = nullptr;

		szNumberOfImportDescriptors = 0;
		szOfImportSection = 0;
		szOfApiAndModuleNames = 0;
		szImportSectionIndex = 0;
		bUseOFT = false;
		szOfOFTArray = 0;
		bNewIatInSection = false;
		bBuildDirectImportsJumpTable = false;
		uSizeOfJumpTable = 0;
	}

	bool rebuildImportTable( const wchar_t* pNewFilePath, std::map<std::uintptr_t, ImportModuleThunk>& vModuleList );
	void enableOFTSupport( );
	void enableNewIatInSection( std::uintptr_t uIATAddress, std::uint32_t uIatSize );

	IATReferenceScan* pIatReferenceScan;
	bool bBuildDirectImportsJumpTable;
private:
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	PIMAGE_THUNK_DATA pThunkData;
	PIMAGE_IMPORT_BY_NAME pImportByName;

	std::size_t szNumberOfImportDescriptors;
	std::size_t szOfImportSection;
	std::size_t szOfApiAndModuleNames;
	std::size_t szImportSectionIndex;

	//OriginalFirstThunk Array in Import Section
	std::size_t szOfOFTArray;
	bool bUseOFT;
	bool bNewIatInSection;
	std::uintptr_t IatAddress;

	std::uint32_t IatSize;

	std::uint32_t uSizeOfJumpTable;

	std::uint32_t uDirectImportsJumpTableRVA;
	std::uint8_t* uJMPTableMemory;
	std::uint32_t uNewIatBaseAddressRVA;


	std::uint32_t fillImportSection( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList );
	std::uint8_t* getMemoryPointerFromRVA( std::uintptr_t uRVA );

	bool createNewImportSection( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList );
	bool buildNewImportTable( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList );
	void setFlagToIATSection( std::uintptr_t uIATAddress );
	std::size_t addImportToImportTable( ImportThunk* pImport, PIMAGE_THUNK_DATA pThunk, PIMAGE_IMPORT_BY_NAME pImportByName, std::uint32_t uSectionOffset );
	std::size_t addImportDescriptor( ImportModuleThunk* pImportModule, std::uint32_t uSectionOffset, std::uint32_t uSectionOffsetOFTArray );

	void calculateImportSizes( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList );

	void addSpecialImportDescriptor( std::uintptr_t uRvaFirstThunk, std::uint32_t uSectionOffsetOFTArray );
	void patchFileForNewIatLocation( );
	void changeIatBaseAddress( std::map<std::uintptr_t, ImportModuleThunk>& vModuleList ) const;
	void patchFileForDirectImportJumpTable( );
};