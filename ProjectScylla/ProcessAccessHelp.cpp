
#include "ProcessAccessHelp.h"
#include "PeParser.h"
#include <Psapi.h>
#include "DeviceNameResolver.h"
#include "WinApi/ntos.h"
#include "Tools/Logs.h"
#include "WinApi/ApiTools.h"
#include "Architecture.h"

HANDLE ProcessAccessHelp::hProcess = 0;

ModuleInfo* ProcessAccessHelp::selectedModule;
DWORD_PTR ProcessAccessHelp::targetImageBase = 0;
DWORD_PTR ProcessAccessHelp::targetSizeOfImage = 0;
DWORD_PTR ProcessAccessHelp::maxValidAddress = 0;

std::vector<ModuleInfo> ProcessAccessHelp::moduleList; //target process module list
std::vector<ModuleInfo> ProcessAccessHelp::ownModuleList; //own module list


_DInst ProcessAccessHelp::decomposerResult[ MAX_INSTRUCTIONS ];
unsigned int ProcessAccessHelp::decomposerInstructionsCount = 0;
_CodeInfo ProcessAccessHelp::decomposerCi = { 0 };

_DecodedInst  ProcessAccessHelp::decodedInstructions[ MAX_INSTRUCTIONS ];
unsigned int  ProcessAccessHelp::decodedInstructionsCount = 0;

BYTE ProcessAccessHelp::fileHeaderFromDisk[ PE_HEADER_BYTES_COUNT ];

bool ProcessAccessHelp::openProcessHandle( DWORD dwPID )
{
	if ( !dwPID )
	{
		LOGS_DEBUG( "openProcessHandle :: Wrong PID, PID %X", dwPID );

		return false;
	}

	if ( hProcess )
	{
		LOGS_DEBUG( "openProcessHandle :: There is already a process handle, HANDLE 0x%p", hProcess );

		return false;
	}

	hProcess = ApiTools::OpenProcess( PROCESS_CREATE_THREAD 
		| PROCESS_VM_OPERATION 
		| PROCESS_QUERY_INFORMATION 
		| PROCESS_VM_READ 
		| PROCESS_VM_WRITE 
		| PROCESS_SUSPEND_RESUME 
		| PROCESS_TERMINATE, FALSE, dwPID );

	if ( !hProcess || hProcess == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "openProcessHandle :: Failed to open handle, PID %X", dwPID );

		hProcess = nullptr;
	}

	return ( hProcess != nullptr );
}

void ProcessAccessHelp::closeProcessHandle( )
{
	if ( hProcess ) {

		ApiTools::CloseHandle( hProcess );

		hProcess = nullptr;
	}

	moduleList.clear( );

	targetImageBase = 0;

	selectedModule = nullptr;
}

bool ProcessAccessHelp::readMemoryPartlyFromProcess( DWORD_PTR address, SIZE_T size, LPVOID dataBuffer )
{
	DWORD_PTR addressPart = 0;
	DWORD_PTR readBytes = 0;
	DWORD_PTR bytesToRead = 0;

	if ( !hProcess ) {
		LOGS_DEBUG( "readMemoryPartlyFromProcess :: hProcess == nullptr" );
		return false;
	}

	if ( readMemoryFromProcess( address, size, dataBuffer ) )
		return true;

	addressPart = address;

	MEMORY_BASIC_INFORMATION memBasic = { 0 };

	do {
		if ( !ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( addressPart ), &memBasic, sizeof( memBasic ) ) ) {
			LOGS_DEBUG( "readMemoryPartlyFromProcess :: Error VirtualQueryEx " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", addressPart, size, GetLastError( ) );
			break;
		}

		bytesToRead = memBasic.RegionSize;

		if ( ( readBytes + bytesToRead ) > size ) {
			bytesToRead = size - readBytes;
		}

		if ( memBasic.State == MEM_COMMIT && memBasic.Protect != PAGE_NOACCESS ) {
			if ( !readMemoryFromProcess( addressPart, bytesToRead, reinterpret_cast<LPVOID>( reinterpret_cast<DWORD_PTR>( dataBuffer ) + readBytes ) ) ) {
				break;
			}
		}
		else {
			ZeroMemory( reinterpret_cast<LPVOID>( reinterpret_cast<DWORD_PTR>( dataBuffer ) + readBytes ), bytesToRead );
		}

		readBytes += bytesToRead;

		addressPart += memBasic.RegionSize;

	} while ( readBytes < size );

	return ( readBytes == size );
}

bool ProcessAccessHelp::writeMemoryToProcess( DWORD_PTR address, SIZE_T size, LPVOID dataBuffer )
{
	SIZE_T lpNumberOfBytesWritten = 0;

	if ( !hProcess )
	{
		LOGS_DEBUG( "writeMemoryFromProcess :: hProcess == nullptr" );

		return false;
	}

	return ( ApiTools::WriteProcessMemory( hProcess, (LPVOID)address, dataBuffer, size, &lpNumberOfBytesWritten ) != FALSE );
}

bool ProcessAccessHelp::readMemoryFromProcess( DWORD_PTR address, SIZE_T size, LPVOID dataBuffer )
{
	SIZE_T lpNumberOfBytesRead = 0;
	DWORD dwProtect = 0;
	bool returnValue = false;

	if ( !hProcess )
	{
		LOGS_DEBUG( "readMemoryFromProcess :: hProcess == nullptr" );
		return false;
	}

	if ( !ApiTools::ReadProcessMemory( hProcess, reinterpret_cast<LPVOID>( address ), dataBuffer, size, &lpNumberOfBytesRead ) )
	{
		LOGS_DEBUG( "readMemoryFromProcess :: Error ReadProcessMemory " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", address, size, GetLastError( ) );

		if ( !ApiTools::VirtualProtectEx( hProcess, reinterpret_cast<LPVOID>( address ), size, PAGE_READONLY, &dwProtect ) )
		{
			LOGS_DEBUG( "readMemoryFromProcess :: Error VirtualProtectEx " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", address, size, GetLastError( ) );
			return false;
		}
		else
		{
			if ( !ApiTools::ReadProcessMemory( hProcess, reinterpret_cast<LPVOID>( address ), dataBuffer, size, &lpNumberOfBytesRead ) )
			{
				LOGS_DEBUG( "readMemoryFromProcess :: Error ReadProcessMemory " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", address, size, GetLastError( ) );
				return false;
			}
			ApiTools::VirtualProtectEx( hProcess, reinterpret_cast<LPVOID>( address ), size, dwProtect, &dwProtect );
		}
	}
	else
	{
		returnValue = true;
	}

	if ( returnValue && size != lpNumberOfBytesRead )
	{
		LOGS_DEBUG( "readMemoryFromProcess :: Error ReadProcessMemory read " PRINTF_INTEGER_S " bytes requested " PRINTF_INTEGER_S " bytes", lpNumberOfBytesRead, size );
		return false;
	}

	return true;
}


bool ProcessAccessHelp::decomposeMemory( BYTE* dataBuffer, SIZE_T bufferSize, DWORD_PTR startAddress )
{
	ZeroMemory( &decomposerCi, sizeof( _CodeInfo ) );
	decomposerCi.code = dataBuffer;
	decomposerCi.codeLen = (int)bufferSize;
	decomposerCi.dt = dt;
	decomposerCi.codeOffset = startAddress;

	decomposerInstructionsCount = 0;

	if ( distorm_decompose( &decomposerCi, decomposerResult, sizeof( decomposerResult ) / sizeof( decomposerResult[ 0 ] ), &decomposerInstructionsCount ) == DECRES_INPUTERR )
	{
		LOGS_DEBUG( "decomposeMemory :: distorm_decompose == DECRES_INPUTERR" );

		return false;
	}

	return true;
}

bool ProcessAccessHelp::disassembleMemory( BYTE* dataBuffer, SIZE_T bufferSize, DWORD_PTR startOffset )
{
	// Holds the result of the decoding.
	_DecodeResult res;

	// next is used for instruction's offset synchronization.
	// decodedInstructionsCount holds the count of filled instructions' array by the decoder.

	decodedInstructionsCount = 0;

	_OffsetType offset = startOffset;

	res = distorm_decode( offset, dataBuffer, (int)bufferSize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount );

	if ( res == DECRES_INPUTERR )
	{
		LOGS_DEBUG( "disassembleMemory :: res == DECRES_INPUTERR" );

		return false;
	}
	else if ( res == DECRES_SUCCESS )
		return true;
	
	LOGS_DEBUG( "disassembleMemory :: res == %d", res );

	return true; //not all instructions fit in buffer	
}

DWORD_PTR ProcessAccessHelp::findPattern( DWORD_PTR startOffset, DWORD size, BYTE* pattern, const char* mask )
{
	DWORD pos = 0;
	size_t searchLen = strlen( mask ) - 1;

	for ( DWORD_PTR retAddress = startOffset; retAddress < startOffset + size; retAddress++ )
	{
		if ( *reinterpret_cast<BYTE*>( retAddress ) == pattern[ pos ] || mask[ pos ] == '?' )
		{
			if ( mask[ pos + 1 ] == 0x00 )
			{
				return ( retAddress - searchLen );
			}
			pos++;
		}
		else
			pos = 0;
	}
	return 0;
}

bool ProcessAccessHelp::readHeaderFromCurrentFile( const WCHAR* filePath )
{
	return readHeaderFromFile( fileHeaderFromDisk, sizeof( fileHeaderFromDisk ), filePath );
}

DWORD ProcessAccessHelp::getFileSize( const WCHAR* filePath )
{
	HANDLE hFile = CreateFile( filePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );

	if ( hFile == INVALID_HANDLE_VALUE )
		return 0;

	auto fileSize = getFileSize( hFile );

	CloseHandle( hFile );

	return fileSize;
}

DWORD ProcessAccessHelp::getFileSize( HANDLE hFile )
{
	if ( hFile == INVALID_HANDLE_VALUE || hFile == nullptr )
	{
		LOGS_DEBUG( "ProcessAccessHelp::getFileSize :: Invalid handle" );
		return 0;
	}

	LARGE_INTEGER lpFileSize = { 0 };
	if ( !GetFileSizeEx( hFile, &lpFileSize ) )
	{
		LOGS_DEBUG( "ProcessAccessHelp::getFileSize :: GetFileSizeEx failed %u", GetLastError( ) );
		return 0;
	}

	return static_cast<DWORD>( lpFileSize.QuadPart );
}

bool ProcessAccessHelp::readMemoryFromFile( HANDLE hFile, LONG offset, DWORD size, LPVOID dataBuffer )
{
	if ( hFile == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "readMemoryFromFile :: hFile invalid" );
		return false;
	}

	DWORD lpNumberOfBytesRead = 0;

	DWORD retValue = SetFilePointer( hFile, offset, nullptr, FILE_BEGIN );

	if ( retValue == INVALID_SET_FILE_POINTER && GetLastError( ) != NO_ERROR )
	{
		LOGS_DEBUG( "readMemoryFromFile :: SetFilePointer failed error %u", GetLastError( ) );
		return false;
	}

	if ( !ReadFile( hFile, dataBuffer, size, &lpNumberOfBytesRead, nullptr ) )
	{
		LOGS_DEBUG( "readMemoryFromFile :: ReadFile failed - size %d - error %u", size, GetLastError( ) );
		return false;
	}

	return true;
}

bool ProcessAccessHelp::writeMemoryToNewFile( const WCHAR* file, DWORD size, LPCVOID dataBuffer )
{
	HANDLE hFile = CreateFile( file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );

	if ( hFile == INVALID_HANDLE_VALUE )
		return false;
	
	bool resultValue = writeMemoryToFile( hFile, 0, size, dataBuffer );

	CloseHandle( hFile );

	return resultValue;
}

bool ProcessAccessHelp::writeMemoryToFile( HANDLE hFile, LONG offset, DWORD size, LPCVOID dataBuffer )
{
	if ( hFile == INVALID_HANDLE_VALUE || dataBuffer == nullptr )
	{
		LOGS_DEBUG( "writeMemoryToFile :: Invalid parameters" );
		return false;
	}

	DWORD lpNumberOfBytesWritten = 0;

	DWORD retValue = SetFilePointer( hFile, offset, nullptr, FILE_BEGIN );

	if ( retValue == INVALID_SET_FILE_POINTER && GetLastError( ) != NO_ERROR )
	{
		LOGS_DEBUG( "writeMemoryToFile :: SetFilePointer failed error %u", GetLastError( ) );
		return false;
	}

	if ( !WriteFile( hFile, dataBuffer, size, &lpNumberOfBytesWritten, nullptr ) )
	{
		LOGS_DEBUG( "writeMemoryToFile :: WriteFile failed - size %d - error %u", size, GetLastError( ) );
		return false;
	}

	return true;
}

bool ProcessAccessHelp::writeMemoryToFileEnd( HANDLE hFile, DWORD size, LPCVOID dataBuffer )
{
	DWORD lpNumberOfBytesWritten = 0;

	if ( hFile != INVALID_HANDLE_VALUE && hFile != nullptr )
	{
		SetFilePointer( hFile, 0, nullptr, FILE_END );

		if ( WriteFile( hFile, dataBuffer, size, &lpNumberOfBytesWritten, nullptr ) )
		{
			return true;
		}

		LOGS_DEBUG( "writeMemoryToFileEnd :: WriteFile failed - size %d - error %u", size, GetLastError( ) );

		return false;
	}

	LOGS_DEBUG( "writeMemoryToFileEnd :: hFile invalid" );
	return false;
}

bool ProcessAccessHelp::readHeaderFromFile( BYTE* buffer, DWORD bufferSize, const WCHAR* filePath )
{
	HANDLE hFile = CreateFileW( filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

	if ( hFile == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "readHeaderFromFile :: INVALID_HANDLE_VALUE %u", GetLastError( ) );
		return false;
	}

	DWORD fileSize = getFileSize( hFile );

	DWORD dwSize = ( fileSize > bufferSize ) ? bufferSize : static_cast<DWORD>( fileSize );

	bool returnValue = readMemoryFromFile( hFile, 0, dwSize, buffer );

	CloseHandle( hFile );

	return returnValue;
}

LPVOID ProcessAccessHelp::createFileMappingViewRead( const WCHAR* filePath )
{
	return createFileMappingView( filePath, GENERIC_READ, PAGE_READONLY | SEC_IMAGE, FILE_MAP_READ );
}

LPVOID ProcessAccessHelp::createFileMappingViewFull( const WCHAR* filePath )
{
	return createFileMappingView( filePath, GENERIC_ALL, PAGE_EXECUTE_READWRITE, FILE_MAP_ALL_ACCESS );
}

LPVOID ProcessAccessHelp::createFileMappingView( const WCHAR* filePath, DWORD accessFile, DWORD flProtect, DWORD accessMap )
{
	HANDLE hFile = CreateFile( filePath, accessFile, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );

	if ( hFile == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "createFileMappingView :: INVALID_HANDLE_VALUE %u", GetLastError( ) );

		return nullptr;
	}

	HANDLE hMappedFile = CreateFileMapping( hFile, nullptr, flProtect, 0, 0, nullptr );

	CloseHandle( hFile );

	if ( hMappedFile == nullptr )
	{
		LOGS_DEBUG( "createFileMappingView :: hMappedFile == nullptr" );

		return nullptr;
	}

	if ( GetLastError( ) == ERROR_ALREADY_EXISTS )
	{
		LOGS_DEBUG( "createFileMappingView :: GetLastError() == ERROR_ALREADY_EXISTS" );

		CloseHandle( hMappedFile );

		return nullptr;
	}

	LPVOID addrMappedDll = MapViewOfFile( hMappedFile, accessMap, 0, 0, 0 );

	if ( addrMappedDll == nullptr )
	{
		LOGS_DEBUG( "createFileMappingView :: addrMappedDll == nullptr" );

		CloseHandle( hMappedFile );

		return nullptr;
	}

	CloseHandle( hMappedFile );

	return addrMappedDll;
}

DWORD ProcessAccessHelp::getProcessByName( const WCHAR* processName )
{
	DWORD dwPID = 0;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	PROCESSENTRY32W pe32 = { .dwSize = sizeof( PROCESSENTRY32W ) };

	if ( !Process32FirstW( hProcessSnap, &pe32 ) )
	{
		LOGS_DEBUG( "getProcessByName :: Error getting first Process" );

		CloseHandle( hProcessSnap );
		return 0;
	}

	do
	{
		if ( !_wcsicmp( pe32.szExeFile, processName ) )
		{
			dwPID = pe32.th32ProcessID;
			break;
		}
	} while ( Process32NextW( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );

	return dwPID;
}

bool ProcessAccessHelp::getProcessModules( HANDLE hProcess, std::vector<ModuleInfo>& moduleList )
{
	ModuleInfo module;
	WCHAR filename[ MAX_PATH * 2 ] = { 0 };
	DWORD cbNeeded = 0;
	DeviceNameResolver deviceNameResolver;

	moduleList.reserve( 20 );

	EnumProcessModules( hProcess, nullptr, 0, &cbNeeded );

	auto hMods = std::unique_ptr<HMODULE[ ]>( new HMODULE[ cbNeeded / sizeof( HMODULE ) ] );

	if ( EnumProcessModules( hProcess, hMods.get( ), cbNeeded, &cbNeeded ) )
	{
		for ( unsigned int i = 1; i < ( cbNeeded / sizeof( HMODULE ) ); i++ ) //skip first module!
		{
			module.modBaseAddr = reinterpret_cast<DWORD_PTR>( hMods[ i ] );
			module.modBaseSize = static_cast<DWORD>( getSizeOfImageProcess( hProcess, module.modBaseAddr ) );
			module.isAlreadyParsed = false;
			module.parsing = false;

			filename[ 0 ] = 0;
			module.fullPath[ 0 ] = 0;

			if ( GetMappedFileNameW( hProcess, reinterpret_cast<LPVOID>( module.modBaseAddr ), filename, _countof( filename ) ) > 0 )
			{
				if ( !deviceNameResolver.resolveDeviceLongNameToShort( filename, module.fullPath ) )
				{
					if ( !GetModuleFileNameExW( hProcess, hMods[ i ], module.fullPath, _countof( module.fullPath ) ) )
					{
						wcscpy_s( module.fullPath, filename );
					}
				}
			}
			else
			{
				GetModuleFileNameExW( hProcess, hMods[ i ], module.fullPath, _countof( module.fullPath ) );
			}

			moduleList.push_back( module );
		}

		return true;
	}

	return false;
}

bool ProcessAccessHelp::getMemoryRegionFromAddress( DWORD_PTR address, DWORD_PTR* memoryRegionBase, SIZE_T* memoryRegionSize )
{
	MEMORY_BASIC_INFORMATION memBasic;

	if ( ApiTools::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( address ), &memBasic, sizeof( MEMORY_BASIC_INFORMATION ) ) != sizeof( MEMORY_BASIC_INFORMATION ) )
	{
		LOGS_DEBUG( "getMemoryRegionFromAddress :: VirtualQueryEx error %u", GetLastError( ) );
		return false;
	}

	*memoryRegionBase = reinterpret_cast<DWORD_PTR>( memBasic.BaseAddress );
	*memoryRegionSize = memBasic.RegionSize;
	return true;
}

bool ProcessAccessHelp::getSizeOfImageCurrentProcess( )
{
	DWORD_PTR newSizeOfImage = getSizeOfImageProcess( ProcessAccessHelp::hProcess, ProcessAccessHelp::targetImageBase );

	if ( newSizeOfImage != 0 )
	{
		ProcessAccessHelp::targetSizeOfImage = newSizeOfImage;
		return true;
	}

	return false;	
}

SIZE_T ProcessAccessHelp::getSizeOfImageProcess( HANDLE processHandle, DWORD_PTR moduleBase )
{
	SIZE_T sizeOfImage = 0;
	MEMORY_BASIC_INFORMATION lpBuffer = { 0 };

	SIZE_T sizeOfImageNative = getSizeOfImageProcessNative( processHandle, moduleBase );

	if ( sizeOfImageNative )
	{
		return sizeOfImageNative;
	}

	WCHAR filenameOriginal[ MAX_PATH * 2 ] = { 0 };
	WCHAR filenameTest[ MAX_PATH * 2 ] = { 0 };

	GetMappedFileNameW( processHandle, reinterpret_cast<LPVOID>( moduleBase ), filenameOriginal, _countof( filenameOriginal ) );

	do
	{
		moduleBase += lpBuffer.RegionSize;
		sizeOfImage += lpBuffer.RegionSize;

		if ( !ApiTools::VirtualQueryEx( processHandle, reinterpret_cast<LPVOID>( moduleBase ), &lpBuffer, sizeof( MEMORY_BASIC_INFORMATION ) ) )
		{
			LOGS_DEBUG( "getSizeOfImageProcess :: VirtualQuery failed %X", GetLastError( ) );

			lpBuffer.Type = 0;

			sizeOfImage = 0;
		}

		GetMappedFileNameW( processHandle, reinterpret_cast<LPVOID>( moduleBase ), filenameTest, _countof( filenameTest ) );

		if ( _wcsicmp( filenameOriginal, filenameTest ) != 0 ) // Problem: 2 modules without free space
		{
			break;
		}

	} while ( lpBuffer.Type == MEM_IMAGE );

	return sizeOfImage;
}

DWORD ProcessAccessHelp::getEntryPointFromFile( const WCHAR* filePath )
{
	PeParser peFile( filePath, false );

	return peFile.getEntryPoint( );
}

bool ProcessAccessHelp::createBackupFile( const WCHAR* filePath )
{
	std::wstring backupFilePath = filePath;
	backupFilePath += L".bak"; // Append .bak to the original file path

	BOOL retValue = CopyFile( filePath, backupFilePath.c_str( ), FALSE );

	if ( !retValue )
	{
		LOGS_DEBUG( "createBackupFile :: CopyFile failed with error 0x%X", GetLastError( ) );
	}

	return retValue != 0;
}

DWORD ProcessAccessHelp::getModuleHandlesFromProcess(const HANDLE hProcess, HMODULE** hMods)
{
    DWORD count = 30;
    DWORD cbNeeded = 0;
    bool notEnough = true;

    std::vector<HMODULE> modules(count);

    do
    {
        if (!EnumProcessModules(hProcess, &modules[0], modules.size() * sizeof(HMODULE), &cbNeeded))
        {
            LOGS_DEBUG("getModuleHandlesFromProcess :: EnumProcessModules failed count %lu", modules.size());

            return 0;
        }

        if (modules.size() * sizeof(HMODULE) < cbNeeded)
        {
            modules.resize(cbNeeded / sizeof(HMODULE));
        }
        else
        {
            notEnough = false;
        }
    } while (notEnough);

    // Allocate and copy to output parameter
    *hMods = new HMODULE[modules.size()];

    std::copy(modules.begin(), modules.end(), *hMods);

    return cbNeeded / sizeof(HMODULE);
}

void ProcessAccessHelp::setCurrentProcessAsTarget( )
{
	ProcessAccessHelp::hProcess = reinterpret_cast<HANDLE>( -1 );
}

bool ProcessAccessHelp::suspendProcess( )
{
	return NT_SUCCESS( NtSuspendProcess( ProcessAccessHelp::hProcess ) );
}

bool ProcessAccessHelp::resumeProcess( )
{
	return NT_SUCCESS( NtResumeProcess( ProcessAccessHelp::hProcess ) );
}

bool ProcessAccessHelp::terminateProcess( )
{
	return NT_SUCCESS( NtTerminateProcess( ProcessAccessHelp::hProcess, 0 ) );
}

bool ProcessAccessHelp::isPageAccessable( DWORD Protect )
{
	if ( Protect & PAGE_NOCACHE ) Protect ^= PAGE_NOCACHE;
	if ( Protect & PAGE_GUARD ) Protect ^= PAGE_GUARD;
	if ( Protect & PAGE_WRITECOMBINE ) Protect ^= PAGE_WRITECOMBINE;

	return ( Protect != PAGE_NOACCESS );
}

bool ProcessAccessHelp::isPageExecutable( DWORD Protect )
{
	if ( Protect & PAGE_NOCACHE ) Protect ^= PAGE_NOCACHE;
	if ( Protect & PAGE_GUARD ) Protect ^= PAGE_GUARD;
	if ( Protect & PAGE_WRITECOMBINE ) Protect ^= PAGE_WRITECOMBINE;

	switch ( Protect )
	{
	case PAGE_EXECUTE:
	case PAGE_EXECUTE_READ:
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
	{
		return true;
	}
	default:
	return false;
	}
}

SIZE_T ProcessAccessHelp::getSizeOfImageProcessNative( HANDLE processHandle, DWORD_PTR moduleBase )
{
	MEMORY_REGION_INFORMATION memRegion = { 0 };

	SIZE_T retLen = 0;

	return ( ApiTools::QueryVirtualMemory( processHandle, reinterpret_cast<PVOID>( moduleBase ),
		MemoryRegionInformation, &memRegion, sizeof( MEMORY_REGION_INFORMATION ), &retLen ) == 0ul )
		? memRegion.RegionSize : 0;
}
