#include "RemoteModule.h"
#include "ntos.h"
#include "../Tools/Logs.h"
#include <vector>
#include "ApiTools.h"
#include <functional>

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

	if ( !ReadMemory( hProcess, PebBaseAddress, &Peb, sizeof( Peb ) ) )
	{
		LOGS( "[-] - [REMH] Get peb fail 1" );
		return false;
	}

	if ( !ReadMemory( hProcess, Peb.Ldr, &PebLdr, sizeof( PebLdr ) ) )
	{
		LOGS( "[-] - [REMH] Get ldr fail 1" );
		return false;
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

	if ( !ReadMemory( hProcess, PebBaseAddress32, &Peb32, sizeof( Peb32 ) ) )
	{
		LOGS( "[-] - [REMH] Get peb fail 1" );
		return false;
	}

	PEB_LDR_DATA32 PebLdr{ };

	if ( !ReadMemory( hProcess, reinterpret_cast<LPCVOID>(
		static_cast<size_t>( Peb32.Ldr ) ), &PebLdr, sizeof( PebLdr ) ) )
	{
		LOGS( "[-] - [REMH] Get Ldr fail 1" );
		return false;
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

std::wstring RemoteModule::GetFullModulePathFromBase( HANDLE hProcess, HMODULE hModule, bool bIs64bit ) {

	auto pResultLdrEntry = GetModuleLdrEntryFromBase( hProcess, hModule, bIs64bit );

	if ( !pResultLdrEntry )
	{
		return L"";
	}

	if ( !bIs64bit )
	{
		LDR_DATA_TABLE_ENTRY32* pLdrEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY32*>( pResultLdrEntry.get( ) );

		wchar_t wcsBaseDllName[ MAX_PATH ] = { 0 };

		if ( pLdrEntry->BaseDllName.Length > 0 )
		{
			if ( !ReadMemory( hProcess, reinterpret_cast<LPCVOID>( static_cast<size_t>( pLdrEntry->BaseDllName.Buffer ) ),
				&wcsBaseDllName, pLdrEntry->BaseDllName.Length ) )
			{
				LOGS( "[-] - [REMH] Could not read list entry DLL name." );

				return L"";
			}
		}

		return wcsBaseDllName;
	}

	LDR_DATA_TABLE_ENTRY* pLdrEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>( pResultLdrEntry.get( ) );

	wchar_t wcsBaseDllName[ MAX_PATH ] = { 0 };

	if ( pLdrEntry->BaseDllName.Length > 0 )
	{
		if ( !ReadMemory( hProcess, pLdrEntry->BaseDllName.Buffer, &wcsBaseDllName, pLdrEntry->BaseDllName.Length ) )
		{
			LOGS( "[-] - [REMH] Could not read list entry DLL name." );

			return L"";
		}
	}

	return wcsBaseDllName;
}