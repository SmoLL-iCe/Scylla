#include "RemoteModule.h"
#include "ntos.h"
#include "../Tools/Logs.h"
#include <vector>
#include "ApiRemote.h"
#include <functional>
#include "../DeviceNameResolver.h"

template <typename A1 = void*>
bool ReadMemory( HANDLE hProcess, A1 Address, void* pBuffer, const SIZE_T Size )
{
	return ApiRemote::ReadData( hProcess, Address, pBuffer, Size );
}

void* RemoteModule::GetProcessPeb( HANDLE hProcess, bool bIs64bit ) {

	//if ( bIsKernelMode ) {
	//	return ( bIs64bit ) ? nt::GetProcessPeb( hProcess ) : nt::GetProcessPeb32( hProcess );
	//}

	if ( !bIs64bit )
	{
		void* PebBaseAddress = 0;

		NTSTATUS Status = NtQueryInformationProcess( 
			hProcess, ProcessWow64Information, &PebBaseAddress, sizeof( ULONG_PTR ), 0 );

		if ( !NT_SUCCESS( Status ) )
			return nullptr;

		return PebBaseAddress;
	}

	std::vector<std::uint8_t> pPbi( sizeof( PROCESS_BASIC_INFORMATION ), 0 );

	ULONG dwSizeNeeded = 0;

	do
	{
		NTSTATUS Status = NtQueryInformationProcess( hProcess, ProcessBasicInformation, pPbi.data( ), static_cast<LONG>( pPbi.size( ) ), &dwSizeNeeded );

		if ( Status >= 0 && pPbi.size( ) < dwSizeNeeded )
		{
			pPbi.clear( );
			pPbi.reserve( dwSizeNeeded );
			pPbi.resize( dwSizeNeeded );
		}
		else if ( Status == 0 )
		{
			return reinterpret_cast<PPROCESS_BASIC_INFORMATION>( pPbi.data( ) )->PebBaseAddress;
		}

	} while ( dwSizeNeeded > pPbi.size( ) );

	return nullptr;
};

static 
bool EnumModulesEntry( HANDLE hProcess, std::function<bool( LDR_DATA_TABLE_ENTRY* )> fnCallback ) {

	PEB Peb{ };

	PEB_LDR_DATA PebLdr{ };

	auto PebBaseAddress = RemoteModule::GetProcessPeb( hProcess, true );

	LOGS( "[!] - [REMH] PebBaseAddress 0x%p", PebBaseAddress );

	if ( !PebBaseAddress )
	{
		return false;
	}

	for ( size_t i = 0; i < 5; i++ ) // when the process starting, the PEB is not initialized
	{
		if ( !ReadMemory( hProcess, PebBaseAddress, &Peb, sizeof( Peb ) ) )
		{
			LOGS( "[-] - [REMH] Get peb fail 1" );
			return false;
		}

		if ( !Peb.Ldr )
		{
			Sleep( 100 );
			continue;
		}

		if ( !ReadMemory( hProcess, Peb.Ldr, &PebLdr, sizeof( PebLdr ) ) )
		{
			LOGS( "[-] - [REMH] Get ldr fail 1" );
			return false;
		}

		break;
	}

	LIST_ENTRY* pLdrListHead = PebLdr.InLoadOrderModuleList.Flink;

	LIST_ENTRY* pLdrCurrentNode = PebLdr.InLoadOrderModuleList.Flink;

	do
	{
		LDR_DATA_TABLE_ENTRY lstEntry = { 0 };

		if ( !ReadMemory( hProcess, pLdrCurrentNode, &lstEntry, sizeof( LDR_DATA_TABLE_ENTRY ) ) )
		{
			LOGS( "[-] - [REMH] Could not read list entry from LDR list." );

			break;
		}

		pLdrCurrentNode = lstEntry.InLoadOrderLinks.Flink;

		if ( fnCallback( &lstEntry ) ) { 
			return true;
		}

	} while ( pLdrListHead != pLdrCurrentNode );
	
	return false;
}

static
bool EnumModulesEntry32( HANDLE hProcess, std::function<bool( LDR_DATA_TABLE_ENTRY32* )> fnCallback ) {

	auto PebBaseAddress32 = RemoteModule::GetProcessPeb( hProcess, false );

	LOGS( "[!] - [REMH] PebBaseAddress32 0x%p", PebBaseAddress32 );

	if ( !PebBaseAddress32 )
		return false;


	_PEB32 Peb32{ };

	PEB_LDR_DATA32 PebLdr{ };

	for ( size_t i = 0; i < 5; i++ ) // when the process starting, the PEB is not initialized
	{
		if ( !ReadMemory( hProcess, PebBaseAddress32, &Peb32, sizeof( Peb32 ) ) )
		{
			LOGS( "[-] - [REMH] Get peb fail 1" );
			return false;
		}

		if ( Peb32.Ldr == 0 )
		{
			Sleep( 100 );
			continue;
		}

		if ( !ReadMemory( hProcess, reinterpret_cast<LPCVOID>(
			static_cast<size_t>( Peb32.Ldr ) ), &PebLdr, sizeof( PebLdr ) ) )
		{
			LOGS( "[-] - [REMH] Get Ldr fail 1" );
			return false;
		}

		break;
	}

	LIST_ENTRY32* pLdrListHead = reinterpret_cast<LIST_ENTRY32*>(
		static_cast<size_t>( PebLdr.InLoadOrderModuleList.Flink ) );

	LIST_ENTRY32* pLdrCurrentNode = reinterpret_cast<LIST_ENTRY32*>(
		static_cast<size_t>( PebLdr.InLoadOrderModuleList.Flink ) );

	do
	{
		LDR_DATA_TABLE_ENTRY32 lstEntry = { 0 };

		if ( !ReadMemory( hProcess, (void*)pLdrCurrentNode, &lstEntry, sizeof( LDR_DATA_TABLE_ENTRY32 ) ) )
		{
			LOGS( "[-] - [REMH] Could not read list entry from LDR list." );

			break;
		}

		pLdrCurrentNode = reinterpret_cast<LIST_ENTRY32*>( static_cast<size_t>( lstEntry.InLoadOrderLinks.Flink ) );

		if ( fnCallback( &lstEntry ) )
			return true;


	} while ( pLdrListHead != pLdrCurrentNode );

	return false;
}

void RemoteModule::EnumModulesInfo( HANDLE hProcess, bool bIs64bit, std::function<bool( sPebModuleInfo* )> fnCallback ) {

	if ( bIs64bit )
	{
		EnumModulesEntry( hProcess, [ & ]( LDR_DATA_TABLE_ENTRY* pEntry ) -> bool {

			sPebModuleInfo ModuleInfo{ };

			if ( pEntry->BaseDllName.Length > 0 )
			{
				if ( !ReadMemory( hProcess, pEntry->BaseDllName.Buffer, ModuleInfo.BaseDllName, pEntry->BaseDllName.Length ) )
				{
					LOGS( "[-] - [REMH] Could not read list entry DLL name");

					return false;
				}
			}


			if ( pEntry->FullDllName.Length > 0 )
			{
				if ( !ReadMemory( hProcess, pEntry->FullDllName.Buffer, ModuleInfo.FullDllName, pEntry->FullDllName.Length ) )
				{
					LOGS( "[-] - [REMH] Could not read list entry DLL FullDllName" );

					return false;
				}
			}

			ModuleInfo.SizeOfImage = pEntry->SizeOfImage;
			ModuleInfo.DllBase     = pEntry->DllBase;
			ModuleInfo.EntryPoint  = pEntry->EntryPoint;

			return fnCallback( &ModuleInfo );
		} );
	}
	else
	{
		EnumModulesEntry32( hProcess, [ & ]( LDR_DATA_TABLE_ENTRY32* pEntry ) -> bool {

			sPebModuleInfo ModuleInfo{ };

			if ( pEntry->BaseDllName.Length > 0 )
			{
				if ( !ReadMemory( hProcess, reinterpret_cast<LPCVOID>( static_cast<size_t>( pEntry->BaseDllName.Buffer ) ), ModuleInfo.BaseDllName, pEntry->BaseDllName.Length ) )
				{
					LOGS( "[-] - [REMH] Could not read list entry DLL name." );

					return false;
				}
			}

			if ( pEntry->FullDllName.Length > 0 )
			{
				if ( !ReadMemory( hProcess, reinterpret_cast<LPCVOID>( static_cast<size_t>( pEntry->FullDllName.Buffer ) ), ModuleInfo.FullDllName, pEntry->FullDllName.Length ) )
				{
					LOGS( "[-] - [REMH] Could not read list entry DLL FullDllName." );

					return false;
				}
			}

			ModuleInfo.SizeOfImage = pEntry->SizeOfImage;
			ModuleInfo.DllBase     = reinterpret_cast<LPVOID>( static_cast<std::size_t>( pEntry->DllBase ) );
			ModuleInfo.EntryPoint  = reinterpret_cast<LPVOID>( static_cast<std::size_t>( pEntry->EntryPoint ) );

			return fnCallback( &ModuleInfo );
		} );
	}
}

static 
std::unique_ptr<std::uint8_t[]> GetModuleLdrEntryHandleW( HANDLE hProcess,
	const wchar_t* pModuleName, bool bIs64bit, bool bCaseSensitive )
{
	auto PwToLowercase = [ ]( const wchar_t* str ) -> std::unique_ptr<wchar_t[ ]> {

			int len = lstrlenW( str );

			std::unique_ptr<wchar_t[]> lowercaseStr = std::unique_ptr<wchar_t[]>( new wchar_t[ len + 1 ] );

			if ( !lowercaseStr ) {
				return nullptr;
			}

			wcscpy_s( lowercaseStr.get( ), len + 1, str );

			CharLowerBuffW( lowercaseStr.get( ), len );

			return lowercaseStr;
		};


	std::unique_ptr<wchar_t[ ]> pModuleNameLowercase = nullptr;

	if ( !bCaseSensitive ) { 

		pModuleNameLowercase = PwToLowercase( pModuleName );

		pModuleName = pModuleNameLowercase.get( );
	}

	std::unique_ptr<std::uint8_t[ ]> pLdrEntry = nullptr;

	if ( bIs64bit )
	{
		if ( !EnumModulesEntry( hProcess, [ & ]( LDR_DATA_TABLE_ENTRY* pEntry ) -> bool {

			wchar_t wcsBaseDllName[ MAX_PATH ] = { 0 };

			if ( pEntry->BaseDllName.Length > 0 )
			{
				if ( !ReadMemory( hProcess, pEntry->BaseDllName.Buffer,
					&wcsBaseDllName, pEntry->BaseDllName.Length ) )
				{
					LOGS( "[-] - [REMH] Could not read list entry DLL name");

					return false;
				}
			}

			//LOGS( "[-] - [REMH] BaseDllName = %ls", wcsBaseDllName );

			if ( pEntry->DllBase != nullptr && pEntry->SizeOfImage != 0 )
			{
				if ( !bCaseSensitive ) {
					CharLowerBuffW( wcsBaseDllName, pEntry->BaseDllName.Length );
				}

				if ( _wcsicmp( wcsBaseDllName, pModuleName ) == 0 )
				{
					pLdrEntry = std::unique_ptr<std::uint8_t[ ]>( new std::uint8_t[ sizeof( LDR_DATA_TABLE_ENTRY ) ] );

					if ( !pLdrEntry )
						return false;

					std::memcpy( pLdrEntry.get( ), pEntry, sizeof( LDR_DATA_TABLE_ENTRY ) );

					return true;
				}
			}

			return false;
			} ) )
		{
			return nullptr;
		}
	}
	else
	{

		if ( !EnumModulesEntry32( hProcess, [ & ]( LDR_DATA_TABLE_ENTRY32* pEntry ) -> bool {

			wchar_t wcsBaseDllName[ MAX_PATH ] = { 0 };

			if ( pEntry->BaseDllName.Length > 0 )
			{
				if ( !ReadMemory( hProcess, reinterpret_cast<LPCVOID>( static_cast<size_t>( pEntry->BaseDllName.Buffer ) ),
					&wcsBaseDllName, pEntry->BaseDllName.Length ) )
				{
					LOGS( "[-] - [REMH] Could not read list entry DLL name." );

					return false;
				}
			}

			if ( pEntry->DllBase != 0 && pEntry->SizeOfImage != 0 )
			{
				if ( !bCaseSensitive ) {
					CharLowerBuffW( wcsBaseDllName, pEntry->BaseDllName.Length );
				}

				LOGS( "[-] - [REMH] BaseDllName = %ls, %ls", wcsBaseDllName, pModuleName );

				if ( _wcsicmp( wcsBaseDllName, pModuleName ) == 0 )
				{
					pLdrEntry = std::unique_ptr<std::uint8_t[ ]>( new std::uint8_t[ sizeof( LDR_DATA_TABLE_ENTRY32 ) ] );

					if ( !pLdrEntry )
						return false;

					std::memcpy( pLdrEntry.get( ), pEntry, sizeof( LDR_DATA_TABLE_ENTRY32 ) );

					return true;
				}
			}
			return false;
			} ) ) {
			return nullptr;
		}
	}

	return pLdrEntry;
}

static 
std::unique_ptr<std::uint8_t[]> GetModuleLdrEntryFromBase( HANDLE hProcess,
	HMODULE pModule, bool bIs64bit )
{
	std::unique_ptr<std::uint8_t[ ]> pLdrEntry = nullptr;

	if ( bIs64bit )
	{
		if ( !EnumModulesEntry( hProcess, [ & ]( LDR_DATA_TABLE_ENTRY* pEntry ) -> bool {

			if ( reinterpret_cast<HMODULE>( pEntry->DllBase ) == pModule )
			{
				pLdrEntry = std::unique_ptr<std::uint8_t[ ]>( new std::uint8_t[ sizeof( LDR_DATA_TABLE_ENTRY ) ] );

				if ( !pLdrEntry )
					return false;

				std::memcpy( pLdrEntry.get( ), pEntry, sizeof( LDR_DATA_TABLE_ENTRY ) );

				return true;
			}

			return false;
			} ) )
		{
			return nullptr;
		}
	}
	else
	{

		if ( !EnumModulesEntry32( hProcess, [ & ]( LDR_DATA_TABLE_ENTRY32* pEntry ) -> bool {

			if ( reinterpret_cast<HMODULE>(
				static_cast<std::size_t>( pEntry->DllBase ) ) == pModule )
			{
				pLdrEntry = std::unique_ptr<std::uint8_t[ ]>( new std::uint8_t[ sizeof( LDR_DATA_TABLE_ENTRY32 ) ] );

				if ( !pLdrEntry )
					return false;

				std::memcpy( pLdrEntry.get( ), pEntry, sizeof( LDR_DATA_TABLE_ENTRY32 ) );

				return true;
			}

			return false;
			} ) ) {
			return nullptr;
		}
	}

	return pLdrEntry;
}

HMODULE RemoteModule::GetHandleW( HANDLE hProcess,
	const wchar_t* pModuleName, 
	ULONG* pOutModuleSize, 
	bool bIs64bit, 
	bool bCaseSensitive )
{
	auto pResultLdrEntry = GetModuleLdrEntryHandleW( hProcess, pModuleName, bIs64bit, bCaseSensitive );

	if ( !pResultLdrEntry )
	{
		return nullptr;
	}

	if ( !bIs64bit )
	{
		LDR_DATA_TABLE_ENTRY32* pLdrEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY32*>( pResultLdrEntry.get( ) );

		auto pBase = reinterpret_cast<HMODULE>( static_cast<size_t>( pLdrEntry->DllBase ) );

		if ( pOutModuleSize )
			*pOutModuleSize = pLdrEntry->SizeOfImage;

		return pBase;
	}

	LDR_DATA_TABLE_ENTRY* pLdrEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>( pResultLdrEntry.get( ) );

	auto pBase = reinterpret_cast<HMODULE>( pLdrEntry->DllBase );

	if ( pOutModuleSize )
		*pOutModuleSize = pLdrEntry->SizeOfImage;

	return pBase;
}

std::size_t RemoteModule::GetSizeOfModuleFromPage( HANDLE hProcess, PVOID pModule )
{
	std::uintptr_t uModuleBase = reinterpret_cast<std::uintptr_t>( pModule );

	std::size_t szOfImage = 0;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	std::wstring strFileNameOriginal = RemoteModule::GetModulePathFromPage( hProcess, pModule );

	if ( strFileNameOriginal.empty( ) )
		return 0;

	do
	{
		uModuleBase += mbi.RegionSize;
		szOfImage += mbi.RegionSize;

		if ( !ApiRemote::VirtualQueryEx( hProcess, reinterpret_cast<LPVOID>( uModuleBase ), &mbi, sizeof( MEMORY_BASIC_INFORMATION ) ) )
		{
			LOGS_DEBUG( "getSizeOfImageProcess :: VirtualQuery failed %X", GetLastError( ) );

			mbi.Type = 0;

			szOfImage = 0;
		}

		std::wstring strFileNameTest = RemoteModule::GetModulePathFromPage( hProcess, reinterpret_cast<PVOID>( uModuleBase ) );

		if ( strFileNameOriginal.compare( strFileNameTest ) != 0 ) // Problem: 2 modules without free space
		{
			break;
		}

	} while ( mbi.Type == MEM_IMAGE );

	return szOfImage;
}

// https://doxygen.reactos.org/de/d86/dll_2win32_2psapi_2psapi_8c_source.html
static 
std::wstring GetProcessImageFileNameW( HANDLE hProcess )
{
	const SIZE_T nSize = MAX_PATH;

	SIZE_T BufferSize = sizeof( UNICODE_STRING ) + ( nSize * sizeof( WCHAR ) );

	std::unique_ptr<std::uint8_t[]> pImageFileName( new std::uint8_t[ BufferSize ] );

	PUNICODE_STRING ImageFileName = reinterpret_cast<PUNICODE_STRING>( pImageFileName.get( ) );

	if ( ImageFileName == nullptr )
	{
		return L"";
	}

	NTSTATUS Status = ApiRemote::QueryInformationProcess( hProcess,
		ProcessImageFileName,
		ImageFileName,
		static_cast<ULONG>( BufferSize ),
		nullptr );

	if ( Status == STATUS_INFO_LENGTH_MISMATCH )
	{
		Status = STATUS_BUFFER_TOO_SMALL;
	}

	if ( !NT_SUCCESS( Status ) )
	{
		SetLastError( RtlNtStatusToDosError( Status ) );
		return L"";
	}

	std::wstring strImageFileName = ImageFileName->Buffer;

	DWORD Len = ImageFileName->Length / sizeof( WCHAR );

	if ( Len < nSize )
	{
		strImageFileName[ Len ] = UNICODE_NULL;
	}

	return DeviceNameResolver::resolveDeviceLongNameToShort( strImageFileName );
}

std::wstring RemoteModule::GetModulePathFromPage( HANDLE hProcess, PVOID pModule )
{
	std::unique_ptr<wchar_t[]> pBuff( new wchar_t[ MAX_PATH * 2 ] );

	if ( ApiRemote::QueryVirtualMemory( hProcess, pModule, MemoryMappedFilenameInformation, pBuff.get( ), MAX_PATH * 2, nullptr ) )
		return L"";

	//auto* const pFullName = reinterpret_cast<wchar_t*>( &pBuff[ 16 ] );

	std::wstring strFullName = std::wstring( &pBuff[ 16 ] );

	return DeviceNameResolver::resolveDeviceLongNameToShort( strFullName );
}

std::wstring RemoteModule::GetFullModulePathFromBase( HANDLE hProcess, HMODULE hModule, bool bIs64bit ) {

	if ( !bIs64bit )
	{
		std::wstring strResult = GetModulePathFromPage( hProcess, reinterpret_cast<PVOID>( hModule ) );

		if ( !strResult.empty() )
			return strResult;
	}

	auto pResultLdrEntry = GetModuleLdrEntryFromBase( hProcess, hModule, bIs64bit );

	if ( !pResultLdrEntry )
	{
		std::wstring strResult = GetProcessImageFileNameW( hProcess );

		return ( !strResult.empty( ) ) ? strResult : L"";
	}

	if ( !bIs64bit )
	{
		LDR_DATA_TABLE_ENTRY32* pLdrEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY32*>( pResultLdrEntry.get( ) );

		wchar_t wcsFullDllName[ MAX_PATH ] = { 0 };

		if ( pLdrEntry->FullDllName.Length > 0 )
		{
			if ( !ReadMemory( hProcess, reinterpret_cast<LPCVOID>( static_cast<size_t>( pLdrEntry->FullDllName.Buffer ) ),
				wcsFullDllName, pLdrEntry->FullDllName.Length + 2 ) )
			{
				LOGS( "[-] - [REMH] Could not read list entry DLL name." );

				return L"";
			}
		}

		return wcsFullDllName;
	}

	LDR_DATA_TABLE_ENTRY* pLdrEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>( pResultLdrEntry.get( ) );

	wchar_t wcsBaseDllName[ MAX_PATH ] = { 0 };

	if ( pLdrEntry->FullDllName.Length > 0 )
	{
		if ( !ReadMemory( hProcess, pLdrEntry->FullDllName.Buffer, &wcsBaseDllName, pLdrEntry->FullDllName.Length + 2 ) )
		{
			LOGS( "[-] - [REMH] Could not read list entry DLL name." );

			return  L"";
		}
	}

	return wcsBaseDllName;
}