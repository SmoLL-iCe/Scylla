
#include "ProcessAccessHelp.h"
#include "PeParser.h"
#include "DeviceNameResolver.h"
#include "WinApi/ntos.h"
#include "Tools/Logs.h"
#include "WinApi/ApiRemote.h"
#include "Architecture.h"
#include "ProcessLister.h"
#include "WinApi/RemoteModule.h"

HANDLE ProcessAccessHelp::hProcess = 0;

std::uintptr_t ProcessAccessHelp::uTargetImageBase = 0;
std::uintptr_t ProcessAccessHelp::uTargetSizeOfImage = 0;
std::uintptr_t ProcessAccessHelp::uMaxValidAddress = 0;

bool ProcessAccessHelp::is64BitProcess = false;
std::vector<ModuleInfo> ProcessAccessHelp::vModuleList; //target process pModule list
std::vector<ModuleInfo> ProcessAccessHelp::vOwnModuleList; //own pModule list


_DInst ProcessAccessHelp::decomposerResult[ MAX_INSTRUCTIONS ];
std::uint32_t ProcessAccessHelp::uDecomposerInstructionsCount = 0;
_CodeInfo ProcessAccessHelp::decomposerCi = { 0 };

_DecodedInst  ProcessAccessHelp::decodedInstructions[ MAX_INSTRUCTIONS ];
std::uint32_t  ProcessAccessHelp::decodedInstructionsCount = 0;

_DecodeType ProcessAccessHelp::dt = Decode64Bits;

std::uint8_t ProcessAccessHelp::fileHeaderFromDisk[ PE_HEADER_BYTES_COUNT ];

bool ProcessAccessHelp::openProcessHandle( std::uint32_t uPID )
{
	if ( !uPID )
	{
		LOGS_DEBUG( "openProcessHandle :: Wrong PID, PID %X", uPID );

		return false;
	}

	if ( hProcess )
	{
		LOGS_DEBUG( "openProcessHandle :: There is already a process handle, HANDLE 0x%p", hProcess );

		return false;
	}

	hProcess = ApiRemote::OpenProcess( PROCESS_CREATE_THREAD
		| PROCESS_VM_OPERATION
		| PROCESS_QUERY_INFORMATION
		| PROCESS_VM_READ
		| PROCESS_VM_WRITE
		| PROCESS_SUSPEND_RESUME
		| PROCESS_TERMINATE, FALSE, uPID );

	if ( !hProcess || hProcess == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "openProcessHandle :: Failed to open handle, PID %X", uPID );

		hProcess = nullptr;
	}

	is64BitProcess = ProcessLister::checkIsProcess64( hProcess ) == PROCESS_64;

	dt = is64BitProcess ? Decode64Bits : Decode32Bits;

	return ( hProcess != nullptr );
}

void ProcessAccessHelp::closeProcessHandle( )
{
	if ( hProcess ) {

		ApiRemote::CloseHandle( hProcess );

		hProcess = nullptr;
	}

	vModuleList.clear( );

	uTargetImageBase = 0;

	//selectedModule = nullptr;
}

bool ProcessAccessHelp::readMemoryPartlyFromProcess( std::uintptr_t uAddress, LPVOID pDataBuffer, std::size_t szSize )
{
	std::uintptr_t addressPart = 0;
	std::uintptr_t readBytes = 0;
	std::uintptr_t bytesToRead = 0;

	if ( !hProcess ) {
		LOGS_DEBUG( "readMemoryPartlyFromProcess :: hProcess == nullptr" );
		return false;
	}

	if ( readRemoteMemory( uAddress, pDataBuffer, szSize ) )
		return true;



	addressPart = uAddress;

	MEMORY_BASIC_INFORMATION memBasic = { 0 };

	do {
		if ( !ApiRemote::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( addressPart ), &memBasic, sizeof( memBasic ) ) ) {
			LOGS_DEBUG( "readMemoryPartlyFromProcess :: Error VirtualQueryEx " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", addressPart, szSize, GetLastError( ) );
			break;
		}

		bytesToRead = memBasic.RegionSize;

		if ( ( readBytes + bytesToRead ) > szSize ) {
			bytesToRead = szSize - readBytes;
		}

		if ( memBasic.State == MEM_COMMIT
			//&& memBasic.Protect != PAGE_NOACCESS 
			) {
			if ( !readRemoteMemory( addressPart, reinterpret_cast<LPVOID>( reinterpret_cast<std::uintptr_t>( pDataBuffer ) + readBytes ), bytesToRead ) ) {
				break;
			}
		}
		else {
			ZeroMemory( reinterpret_cast<LPVOID>( reinterpret_cast<std::uintptr_t>( pDataBuffer ) + readBytes ), bytesToRead );
		}

		readBytes += bytesToRead;

		addressPart += memBasic.RegionSize;

	} while ( readBytes < szSize );

	return ( readBytes == szSize );
}

bool ProcessAccessHelp::writeRemoteMemory( std::uintptr_t uAddress, LPVOID pDataBuffer, std::size_t szSize )
{
	SIZE_T szNumberOfBytesWritten = 0;

	if ( !hProcess )
	{
		LOGS_DEBUG( "writeMemoryFromProcess :: hProcess == nullptr" );

		return false;
	}

	return ( ApiRemote::WriteProcessMemory( hProcess, reinterpret_cast<LPVOID>( uAddress ), pDataBuffer, szSize, &szNumberOfBytesWritten ) != FALSE );
}

bool ProcessAccessHelp::readRemoteMemory( std::uintptr_t uAddress, LPVOID pDataBuffer, std::size_t szSize )
{
	SIZE_T szNumberOfBytesRead = 0;
	DWORD dwProtect = 0;
	bool returnValue = false;

	if ( !hProcess )
	{
		LOGS_DEBUG( "readRemoteMemory :: hProcess == nullptr" );
		return false;
	}

	if ( !ApiRemote::ReadProcessMemory( hProcess, reinterpret_cast<LPVOID>( uAddress ), pDataBuffer, szSize, &szNumberOfBytesRead ) )
	{
		LOGS_DEBUG( "readRemoteMemory :: Error ReadProcessMemory " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", uAddress, szSize, GetLastError( ) );

		if ( !ApiRemote::VirtualProtectEx( hProcess, reinterpret_cast<LPVOID>( uAddress ), szSize, PAGE_READONLY, &dwProtect ) )
		{
			LOGS_DEBUG( "readRemoteMemory :: Error VirtualProtectEx " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", uAddress, szSize, GetLastError( ) );
			return false;
		}
		else
		{
			if ( !ApiRemote::ReadProcessMemory( hProcess, reinterpret_cast<LPVOID>( uAddress ), pDataBuffer, szSize, &szNumberOfBytesRead ) )
			{
				LOGS_DEBUG( "readRemoteMemory :: Error ReadProcessMemory " PRINTF_DWORD_PTR_FULL_S " " PRINTF_DWORD_PTR_FULL_S " err: %u", uAddress, szSize, GetLastError( ) );
				return false;
			}
			ApiRemote::VirtualProtectEx( hProcess, reinterpret_cast<LPVOID>( uAddress ), szSize, dwProtect, &dwProtect );
		}
	}
	else
	{
		returnValue = true;
	}

	if ( returnValue && szSize != szNumberOfBytesRead )
	{
		LOGS_DEBUG( "readRemoteMemory :: Error ReadProcessMemory read " PRINTF_INTEGER_S " bytes requested " PRINTF_INTEGER_S " bytes", szNumberOfBytesRead, szSize );
		return false;
	}

	return true;
}


bool ProcessAccessHelp::decomposeMemory( std::uint8_t* pDataBuffer, std::size_t bufferSize, std::uintptr_t uStartAddress )
{
	ZeroMemory( &decomposerCi, sizeof( _CodeInfo ) );
	decomposerCi.code = pDataBuffer;
	decomposerCi.codeLen = static_cast<int>( bufferSize );
	decomposerCi.dt = dt;
	decomposerCi.codeOffset = uStartAddress;

	uDecomposerInstructionsCount = 0;

	if ( distorm_decompose( &decomposerCi, decomposerResult, sizeof( decomposerResult ) / sizeof( decomposerResult[ 0 ] ), &uDecomposerInstructionsCount ) == DECRES_INPUTERR )
	{
		LOGS_DEBUG( "decomposeMemory :: distorm_decompose == DECRES_INPUTERR" );

		return false;
	}

	return true;
}

bool ProcessAccessHelp::disassembleMemory( std::uint8_t* pDataBuffer, std::size_t bufferSize, std::uintptr_t uStartOffset )
{
	// Holds the result of the decoding.
	_DecodeResult res;

	// next is used for instruction's offset synchronization.
	// decodedInstructionsCount holds the count of filled instructions' array by the decoder.

	decodedInstructionsCount = 0;

	_OffsetType offset = uStartOffset;

	res = distorm_decode( offset, pDataBuffer, static_cast<int>( bufferSize ), dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount );

	if ( res == DECRES_INPUTERR )
	{
		LOGS_DEBUG( "disassembleMemory :: res == DECRES_INPUTERR" );

		return false;
	}
	else if ( res == DECRES_SUCCESS )
		return true;

	LOGS_DEBUG( "disassembleMemory :: res == %d", res );

	return true; //not all instructions fit in pBuffer	
}

std::uintptr_t ProcessAccessHelp::findPattern( std::uintptr_t uStartOffset, std::uint32_t uSize, std::uint8_t* pattern, const char* mask )
{
	std::uint32_t nPos = 0;
	std::size_t szSearchLen = strlen( mask ) - 1;

	for ( std::uintptr_t uRetAddress = uStartOffset; uRetAddress < uStartOffset + uSize; uRetAddress++ )
	{
		if ( *reinterpret_cast<std::uint8_t*>( uRetAddress ) == pattern[ nPos ] || mask[ nPos ] == '?' )
		{
			if ( mask[ nPos + 1 ] == 0x00 )
			{
				return ( uRetAddress - szSearchLen );
			}
			nPos++;
		}
		else
			nPos = 0;
	}
	return 0;
}

bool ProcessAccessHelp::readHeaderFromCurrentFile( const wchar_t* pFilePath )
{
	return readHeaderFromFile( fileHeaderFromDisk, sizeof( fileHeaderFromDisk ), pFilePath );
}

std::uint32_t ProcessAccessHelp::getFileSize( const wchar_t* pFilePath )
{
	HANDLE hFile = CreateFile( pFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );

	if ( hFile == INVALID_HANDLE_VALUE )
		return 0;

	auto uFileSize = getFileSize( hFile );

	CloseHandle( hFile );

	return uFileSize;
}

std::uint32_t ProcessAccessHelp::getFileSize( HANDLE hFile )
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

	return static_cast<std::uint32_t>( lpFileSize.QuadPart );
}

bool ProcessAccessHelp::readMemoryFromFile( HANDLE hFile, LONG lOffset, std::uint32_t uSize, LPVOID pDataBuffer )
{
	if ( hFile == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "readMemoryFromFile :: hFile invalid" );
		return false;
	}

	DWORD dwNumberOfBytesRead = 0;

	DWORD dwResult = SetFilePointer( hFile, lOffset, nullptr, FILE_BEGIN );

	if ( dwResult == INVALID_SET_FILE_POINTER && GetLastError( ) != NO_ERROR )
	{
		LOGS_DEBUG( "readMemoryFromFile :: SetFilePointer failed error %u", GetLastError( ) );
		return false;
	}

	if ( !ReadFile( hFile, pDataBuffer, uSize, &dwNumberOfBytesRead, nullptr ) )
	{
		LOGS_DEBUG( "readMemoryFromFile :: ReadFile failed - size %d - error %u", uSize, GetLastError( ) );
		return false;
	}

	return true;
}

bool ProcessAccessHelp::writeMemoryToNewFile( const wchar_t* pFile, std::uint32_t uSize, LPCVOID pDataBuffer )
{
	HANDLE hFile = CreateFile( pFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );

	if ( hFile == INVALID_HANDLE_VALUE )
		return false;

	bool bResult = writeMemoryToFile( hFile, 0, uSize, pDataBuffer );

	CloseHandle( hFile );

	return bResult;
}

bool ProcessAccessHelp::writeMemoryToFile( HANDLE hFile, LONG lOffset, std::uint32_t uSize, LPCVOID pDataBuffer )
{
	if ( hFile == INVALID_HANDLE_VALUE || pDataBuffer == nullptr )
	{
		LOGS_DEBUG( "writeMemoryToFile :: Invalid parameters" );
		return false;
	}

	DWORD dwNumberOfBytesWritten = 0;

	DWORD dwResult = SetFilePointer( hFile, lOffset, nullptr, FILE_BEGIN );

	if ( dwResult == INVALID_SET_FILE_POINTER && GetLastError( ) != NO_ERROR )
	{
		LOGS_DEBUG( "writeMemoryToFile :: SetFilePointer failed error %u", GetLastError( ) );
		return false;
	}

	if ( !WriteFile( hFile, pDataBuffer, uSize, &dwNumberOfBytesWritten, nullptr ) )
	{
		LOGS_DEBUG( "writeMemoryToFile :: WriteFile failed - size %d - error %u", uSize, GetLastError( ) );
		return false;
	}

	return true;
}

bool ProcessAccessHelp::writeMemoryToFileEnd( HANDLE hFile, std::uint32_t uSize, LPCVOID pDataBuffer )
{
	DWORD dwNumberOfBytesWritten = 0;

	if ( hFile != INVALID_HANDLE_VALUE && hFile != nullptr )
	{
		SetFilePointer( hFile, 0, nullptr, FILE_END );

		if ( WriteFile( hFile, pDataBuffer, uSize, &dwNumberOfBytesWritten, nullptr ) )
		{
			return true;
		}

		LOGS_DEBUG( "writeMemoryToFileEnd :: WriteFile failed - size %d - error %u", uSize, GetLastError( ) );

		return false;
	}

	LOGS_DEBUG( "writeMemoryToFileEnd :: hFile invalid" );
	return false;
}

bool ProcessAccessHelp::readHeaderFromFile( std::uint8_t* pBuffer, std::uint32_t uBufferSize, const wchar_t* pFilePath )
{
	HANDLE hFile = CreateFileW( pFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

	if ( hFile == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "readHeaderFromFile :: INVALID_HANDLE_VALUE %u", GetLastError( ) );
		return false;
	}

	std::uint32_t uFileSize = getFileSize( hFile );

	std::uint32_t uSize = ( uFileSize > uBufferSize ) ? uBufferSize : static_cast<std::uint32_t>( uFileSize );

	bool returnValue = readMemoryFromFile( hFile, 0, uSize, pBuffer );

	CloseHandle( hFile );

	return returnValue;
}

LPVOID ProcessAccessHelp::createFileMappingViewRead( const wchar_t* pFilePath, std::size_t* pSzFileSize )
{
	return createFileMappingView( pFilePath, GENERIC_READ, PAGE_READONLY | SEC_IMAGE, FILE_MAP_READ, pSzFileSize );
}

LPVOID ProcessAccessHelp::createFileMappingViewFull( const wchar_t* pFilePath, std::size_t* pSzFileSize )
{
	return createFileMappingView( pFilePath, GENERIC_ALL, PAGE_EXECUTE_READWRITE, FILE_MAP_ALL_ACCESS, pSzFileSize );
}

LPVOID ProcessAccessHelp::createFileMappingView( const wchar_t* pFilePath, std::uint32_t uAccessFile, std::uint32_t uflProtect, std::uint32_t uAccessMap, std::size_t* pSzFileSize )
{
	HANDLE hFile = CreateFile( pFilePath, uAccessFile, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );

	if ( hFile == INVALID_HANDLE_VALUE )
	{
		LOGS_DEBUG( "createFileMappingView :: INVALID_HANDLE_VALUE %u", GetLastError( ) );

		return nullptr;
	}

	LARGE_INTEGER liFileSize {};

	GetFileSizeEx( hFile, &liFileSize );

	*pSzFileSize = liFileSize.QuadPart;

	HANDLE hMappedFile = CreateFileMappingW( hFile, nullptr, uflProtect, 0, 0, nullptr );

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

	LPVOID pMappedDll = MapViewOfFile( hMappedFile, uAccessMap, 0, 0, 0 );

	if ( pMappedDll == nullptr )
	{
		LOGS_DEBUG( "createFileMappingView :: addrMappedDll == nullptr" );

		CloseHandle( hMappedFile );

		return nullptr;
	}

	CloseHandle( hMappedFile );

	return pMappedDll;
}

std::uint32_t ProcessAccessHelp::getProcessByName( const wchar_t* processName )
{
	std::uint32_t uPID = 0;

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
			uPID = pe32.th32ProcessID;
			break;
		}
	} while ( Process32NextW( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );

	return uPID;
}

bool ProcessAccessHelp::getProcessModules( HANDLE hProcess, std::vector<ModuleInfo>& vModuleList )
{
	vModuleList.clear( );
	vModuleList.reserve( 20 );

	ProcessType archType = ProcessLister::checkIsProcess64( hProcess );

	DWORD dwProcessId = GetProcessId( hProcess );
	if ( dwProcessId == 0 ) {
		return false;
	}

	RemoteModule::EnumModulesInfo( hProcess, archType == PROCESS_64, 
		[ archType, &vModuleList ]( sPebModuleInfo* pModule ) -> bool
		{
			ModuleInfo Module{};

			Module.uModBase = reinterpret_cast<std::uintptr_t>( pModule->DllBase );

			if ( archType == PROCESS_32 && Module.uModBase > 0xFFFFFFFF )
				return false;

			Module.uModBaseSize    = pModule->SizeOfImage;

			Module.isAlreadyParsed = false;

			Module.parsing         = false;

			wcscpy_s( Module.pModulePath, pModule->FullDllName );

			vModuleList.push_back( Module );

			return false;
		} );

	return true;
}

bool ProcessAccessHelp::getMemoryRegionFromAddress( std::uintptr_t uAddress, std::uintptr_t* pMemoryRegionBase, std::size_t* pMemoryRegionSize )
{
	MEMORY_BASIC_INFORMATION mbi;

	if ( ApiRemote::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( uAddress ), &mbi, sizeof( MEMORY_BASIC_INFORMATION ) ) != sizeof( MEMORY_BASIC_INFORMATION ) )
	{
		LOGS_DEBUG( "getMemoryRegionFromAddress :: VirtualQueryEx error %u", GetLastError( ) );
		return false;
	}

	*pMemoryRegionBase = reinterpret_cast<std::uintptr_t>( mbi.BaseAddress );
	*pMemoryRegionSize = mbi.RegionSize;
	return true;
}

bool ProcessAccessHelp::getSizeOfImageCurrentProcess( )
{
	std::uintptr_t uSizeOfImage = getSizeOfImageProcess( ProcessAccessHelp::hProcess, ProcessAccessHelp::uTargetImageBase );

	if ( uSizeOfImage != 0 )
	{
		ProcessAccessHelp::uTargetSizeOfImage = uSizeOfImage;
		return true;
	}

	return false;
}

std::uint32_t ProcessAccessHelp::getSizeOfImageProcess( HANDLE processHandle, std::uintptr_t uModuleBase )
{
	std::size_t szOfImageNative = getSizeOfImageProcessNative( processHandle, uModuleBase );

	if ( szOfImageNative )
		return static_cast<std::uint32_t>( szOfImageNative );
	
	return static_cast<std::uint32_t>( RemoteModule::GetSizeOfModuleFromPage( processHandle, reinterpret_cast<void*>( uModuleBase ) ) );
}

std::uint32_t ProcessAccessHelp::getEntryPointFromFile( const wchar_t* pFilePath )
{
	PeParser peFile( pFilePath, false );

	return peFile.getEntryPoint( );
}

bool ProcessAccessHelp::createBackupFile( const wchar_t* pFilePath )
{
	std::wstring strBackupFilePath = pFilePath;
	strBackupFilePath += L".bak"; // Append .bak to the original file path

	BOOL bResult = CopyFile( pFilePath, strBackupFilePath.c_str( ), FALSE );

	if ( !bResult )
	{
		LOGS_DEBUG( "createBackupFile :: CopyFile failed with error 0x%X", GetLastError( ) );
	}

	return bResult != 0;
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

bool ProcessAccessHelp::isPageAccessable( std::uint32_t uProtect )
{
	if ( uProtect & PAGE_NOCACHE ) uProtect ^= PAGE_NOCACHE;
	if ( uProtect & PAGE_GUARD ) uProtect ^= PAGE_GUARD;
	if ( uProtect & PAGE_WRITECOMBINE ) uProtect ^= PAGE_WRITECOMBINE;

	return ( uProtect != PAGE_NOACCESS );
}

bool ProcessAccessHelp::isPageExecutable( std::uint32_t uProtect )
{
	if ( uProtect & PAGE_NOCACHE ) uProtect ^= PAGE_NOCACHE;
	if ( uProtect & PAGE_GUARD ) uProtect ^= PAGE_GUARD;
	if ( uProtect & PAGE_WRITECOMBINE ) uProtect ^= PAGE_WRITECOMBINE;

	switch ( uProtect )
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

std::size_t ProcessAccessHelp::getSizeOfImageProcessNative( HANDLE processHandle, std::uintptr_t uModuleBase )
{
	MEMORY_REGION_INFORMATION memRegion = { 0 };

	SIZE_T szRetLen = 0;

	return ( ApiRemote::QueryVirtualMemory( processHandle, reinterpret_cast<PVOID>( uModuleBase ),
		MemoryRegionInformation, &memRegion, sizeof( MEMORY_REGION_INFORMATION ), &szRetLen ) == 0ul )
		? memRegion.RegionSize : 0;
}
