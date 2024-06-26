#pragma once
#include <memory>
#include <vector>
#include "ProcessAccessHelp.h"
#include "PeParser.h"
#include "Logger.h"
#include "ApiReader.h"

enum IATReferenceType {
	IAT_REFERENCE_PTR_JMP,
	IAT_REFERENCE_PTR_CALL,
	IAT_REFERENCE_DIRECT_JMP,
	IAT_REFERENCE_DIRECT_CALL,
	IAT_REFERENCE_DIRECT_MOV,
	IAT_REFERENCE_DIRECT_PUSH,
	IAT_REFERENCE_DIRECT_LEA
};

class IATReference
{
public:
	std::uintptr_t uAddressVA; //Address of reference
	std::uintptr_t uTargetPointer; //Place inside IAT
	std::uintptr_t uTargetAddressInIat; //WIN API?
	std::uint8_t uInstructionSize;
	IATReferenceType type;
};


class IATReferenceScan
{
public:

	IATReferenceScan( )
	{
		apiReader = 0;
		IatAddressVA = 0;
		IatSize = 0;
		ImageBase = 0;
		ImageSize = 0;
		iatBackup = 0;
		ScanForDirectImports = false;
		ScanForNormalImports = true;
	}

	~IATReferenceScan( )
	{
		vIatReferenceList.clear( );
		vIatDirectImportList.clear( );

	}

	bool ScanForDirectImports;
	bool ScanForNormalImports;
	bool JunkByteAfterInstruction;
	ApiReader* apiReader;

	void startScan( std::uintptr_t uImageBase, std::uint32_t uImageSize, std::uintptr_t uIATAddress, std::uint32_t uIatSize );
	//void patchNewIatBaseMemory(std::uintptr_t newIatBaseAddress);

	void patchNewIat( std::uintptr_t uStdImagebase, std::uintptr_t newIatBaseAddress, PeParser* peParser );
	void patchDirectJumpTable( std::uintptr_t uImageBase, std::uint32_t uDirectImportsJumpTableRVA, PeParser* peParser, std::uint8_t* pJmpTableMemory, std::uint32_t uNewIatBase );
	void patchDirectImportsMemory( bool junkByteAfterInstruction );
	int numberOfFoundDirectImports( );
	int numberOfFoundUniqueDirectImports( );
	int numberOfDirectImportApisNotInIat( );
	int getSizeInBytesOfJumpTableInSection( );

	void printDirectImportLog( );

	std::uint32_t addAdditionalApisToList( );
private:
	std::uintptr_t NewIatAddressRVA;

	std::uintptr_t IatAddressVA;
	std::uint32_t IatSize;
	std::uintptr_t ImageBase;
	std::uint32_t ImageSize;


	std::unique_ptr<std::uint8_t[ ]> iatBackup {};

	std::vector<IATReference> vIatReferenceList;
	std::vector<IATReference> vIatDirectImportList;

	void scanMemoryPage( PVOID pBaseAddress, std::size_t szRegionSize );
	void analyzeInstruction( _DInst* pInstruction );
	void findNormalIatReference( _DInst* pInstruction );
	void getIatEntryAddress( IATReference* pRef );
	void findDirectIatReferenceCallJmp( _DInst* pInstruction );
	bool isAddressValidImageMemory( std::uintptr_t uAddress );
	void patchReferenceInMemory( IATReference* pRef ) const;

	void patchDirectImportInMemory( IATReference* iter ) const;
	std::uintptr_t lookUpIatForPointer( std::uintptr_t uAddr );
	void findDirectIatReferenceMov( _DInst* pInstruction );
	void findDirectIatReferencePush( _DInst* pInstruction );
	void checkMemoryRangeAndAddToList( IATReference* pRef, _DInst* pInstruction );
	void findDirectIatReferenceLea( _DInst* pInstruction );
	void patchDirectImportInDump32( int nPatchPreFixBytes, int nInstructionSize, std::uint32_t uPatchBytes,
		std::uint8_t* pMemory, std::uint32_t uMemorySize, bool bGenerateReloc, std::uint32_t uPatchOffset, std::uint32_t uSectionRVA );

	void patchDirectImportInDump64( int nPatchPreFixBytes, int nInstructionSize, std::uintptr_t uPatchBytes,
		std::uint8_t* pMemory, std::uint32_t uMemorySize, bool bGenerateReloc, std::uint32_t uPatchOffset, std::uint32_t uSectionRVA );

	void patchDirectJumpTableEntry( std::uintptr_t uTargetIatPointer, std::uintptr_t uStdImagebase,
		std::uint32_t uDirectImportsJumpTableRVA, PeParser* pPeParser, std::uint8_t* pJmpTableMemory, std::uint32_t uNewIatBase );
};

/*
PE64
----------
000000013FF82D87 FF15 137C0A00 CALL QWORD [RIP+0xA7C13]
Result: 000000014002A9A0

000000013F65C952 FF25 F8EA0B00 JMP QWORD [RIP+0xBEAF8]
Result: 000000013F71B450

PE32
----------
0120FFA5 FF15 8C6D2601 CALL std::uint32_t [0x01266D8C]

0120FF52 FF25 D4722601 JMP std::uint32_t [0x012672D4]
*/

