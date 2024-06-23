#pragma once

#include <windows.h>
#include <cstdint>
#include <tlhelp32.h>
#include <vector>

/************************************************************************/
/* distorm                                                              */
/************************************************************************/
#include "../diStorm/include/distorm.h"	
#include "../diStorm/include/mnemonics.h"

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS (200)

/************************************************************************/

class ApiInfo;

class ModuleInfo
{
public:

	wchar_t pModulePath[ MAX_PATH ];
	std::uintptr_t uModBase;
	std::uint32_t uModBaseSize;

	bool isAlreadyParsed;
	bool parsing;

	/*
		for iat rebuilding with duplicate entries:

		ntdll = low nPriority
		kernelbase = low nPriority
		SHLWAPI = low nPriority

		kernel32 = high nPriority

		nPriority = 1 -> normal/high nPriority
		nPriority = 0 -> low nPriority
	*/
	int nPriority;

	std::vector<ApiInfo*> vApiList;

	ModuleInfo( )
	{
		uModBase = 0;
		uModBaseSize = 0;
		nPriority = 1;
		isAlreadyParsed = false;
		parsing = false;
	}

	const wchar_t* getFilename( ) const
	{
		const wchar_t* pSlash = wcsrchr( pModulePath, L'\\' );
		if ( pSlash )
		{
			return pSlash + 1;
		}
		return pModulePath;
	}
};

class ApiInfo
{
public:

	char name[ MAX_PATH ];
	std::uint16_t uHint;
	std::uintptr_t uVA;
	std::uintptr_t uRVA;
	std::uint16_t uOrdinal;
	bool isForwarded;
	ModuleInfo* pModule;
};

class ProcessAccessHelp
{
public:

	static HANDLE hProcess; //OpenProcess handle to target process

	static std::uintptr_t uTargetImageBase;
	static std::uintptr_t uTargetSizeOfImage;
	static std::uintptr_t uMaxValidAddress;

	//static ModuleInfo * selectedModule;

	static std::vector<ModuleInfo> vModuleList; //target process pModule list
	static std::vector<ModuleInfo> vOwnModuleList; //own pModule list

	static const std::size_t PE_HEADER_BYTES_COUNT = 2000;

	static std::uint8_t fileHeaderFromDisk[ PE_HEADER_BYTES_COUNT ];


	//for decomposer
	static _DInst decomposerResult[ MAX_INSTRUCTIONS ];
	static std::uint32_t uDecomposerInstructionsCount;
	static _CodeInfo decomposerCi;

	//distorm :: Decoded instruction information.
	static _DecodedInst decodedInstructions[ MAX_INSTRUCTIONS ];
	static std::uint32_t decodedInstructionsCount;
#ifdef _WIN64
	static const _DecodeType dt = Decode64Bits;
#else
	static const _DecodeType dt = Decode32Bits;
#endif

	/*
	 * Open a new process handle
	 */
	static bool openProcessHandle( std::uint32_t uPID );

	static void closeProcessHandle( );

	/*
	 * Get all modules from a process
	 */
	static bool getProcessModules( HANDLE hProcess, std::vector<ModuleInfo>& vModuleList );


	/*
	 * file mapping view with different access level
	 */
	static LPVOID createFileMappingViewRead( const wchar_t* pFilePath );
	static LPVOID createFileMappingViewFull( const wchar_t* pFilePath );

	/*
	 * Create a file mapping view of a file
	 */
	static LPVOID createFileMappingView( const wchar_t* pFilePath, std::uint32_t uAccessFile, std::uint32_t uflProtect, std::uint32_t uAccessMap );

	/*
	 * Read memory from target process
	 */
	static bool readMemoryFromProcess( std::uintptr_t uAddress, std::size_t szSize, LPVOID pDataBuffer );
	static bool writeMemoryToProcess( std::uintptr_t uAddress, std::size_t szSize, LPVOID pDataBuffer );

	/*
	 * Read memory from target process and ignore no data pages
	 */
	static bool readMemoryPartlyFromProcess( std::uintptr_t uAddress, std::size_t szSize, LPVOID pDataBuffer );

	/*
	 * Read memory from file
	 */
	static bool readMemoryFromFile( HANDLE hFile, LONG lOffset, std::uint32_t uSize, LPVOID pDataBuffer );

	/*
	 * Write memory to file
	 */
	static bool writeMemoryToFile( HANDLE hFile, LONG lOffset, std::uint32_t uSize, LPCVOID pDataBuffer );


	/*
	 * Write memory to new file
	 */
	static bool writeMemoryToNewFile( const wchar_t* pFile, std::uint32_t uSize, LPCVOID pDataBuffer );

	/*
	 * Write memory to file end
	 */
	static bool writeMemoryToFileEnd( HANDLE hFile, std::uint32_t uSize, LPCVOID pDataBuffer );

	/*
	 * Disassemble Memory
	 */
	static bool disassembleMemory( std::uint8_t* pDataBuffer, std::size_t bufferSize, std::uintptr_t uStartOffset );

	static bool decomposeMemory( std::uint8_t* pDataBuffer, std::size_t bufferSize, std::uintptr_t uStartAddress );

	/*
	 * Search for pattern
	 */
	static std::uintptr_t findPattern( std::uintptr_t uStartOffset, std::uint32_t uSize, std::uint8_t* pattern, const char* mask );

	/*
	 * Get process ID by process name
	 */
	static std::uint32_t getProcessByName( const wchar_t* processName );

	/*
	 * Get memory region from address
	 */
	static bool getMemoryRegionFromAddress( std::uintptr_t address, std::uintptr_t* pMemoryRegionBase, std::size_t* pMemoryRegionSize );


	/*
	 * Read PE Header from file
	 */
	static bool readHeaderFromFile( std::uint8_t* pBuffer, std::uint32_t uBufferSize, const wchar_t* pFilePath );

	static bool readHeaderFromCurrentFile( const wchar_t* pFilePath );

	/*
	 * Get real sizeOfImage value
	 */
	static std::uint32_t getSizeOfImageProcess( HANDLE processHandle, std::uintptr_t uModuleBase );

	/*
	 * Get real sizeOfImage value current process
	 */
	static bool getSizeOfImageCurrentProcess( );

	static std::uint32_t getFileSize( HANDLE hFile );
	static std::uint32_t getFileSize( const wchar_t* pFilePath );

	static std::uint32_t getEntryPointFromFile( const wchar_t* pFilePath );

	static bool createBackupFile( const wchar_t* pFilePath );

	static std::uint32_t getModuleHandlesFromProcess( const HANDLE hProcess, HMODULE** hMods );

	static void setCurrentProcessAsTarget( );

	static bool suspendProcess( );
	static bool resumeProcess( );
	static bool terminateProcess( );
	static bool isPageExecutable( std::uint32_t uProtect );
	static bool isPageAccessable( std::uint32_t uProtect );
	static std::size_t getSizeOfImageProcessNative( HANDLE processHandle, std::uintptr_t uModuleBase );
};
