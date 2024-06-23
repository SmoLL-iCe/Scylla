#include "ProcessLister.h"
#include "SystemInformation.h"
#include "Logger.h"
#include "ProcessAccessHelp.h"
#include <algorithm>
#include "Tools/Logs.h"
#include "WinApi/ApiTools.h"
#include <array> 
#include "Tools/Utils.h"

std::vector<Process>& ProcessLister::getProcessList( )
{
    return processList;
}

bool ProcessLister::isWindows64( )
{
#ifdef _WIN64
    //compiled 64bit application
    return true;
#else
    BOOL bIsWow64 = FALSE;

    ApiTools::IsWow64Process( reinterpret_cast<HANDLE>( -1 ), &bIsWow64 );

    return ( bIsWow64 != FALSE );  
#endif
}

DWORD ProcessLister::setDebugPrivileges( )
{
    DWORD err = 0;
    HANDLE hToken = 0;
    TOKEN_PRIVILEGES Debug_Privileges = { 0 };

    if ( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[ 0 ].Luid ) )
    {
        return GetLastError( );
    }

    if ( !OpenProcessToken( reinterpret_cast<HANDLE>( -1 ), TOKEN_ADJUST_PRIVILEGES, &hToken ) )
    {
        err = GetLastError( );
        if ( hToken ) CloseHandle( hToken );
        return err;
    }

    Debug_Privileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
    Debug_Privileges.PrivilegeCount = 1;

    AdjustTokenPrivileges( hToken, false, &Debug_Privileges, 0, NULL, NULL );

    CloseHandle( hToken );

    return GetLastError( );
}

ProcessType ProcessLister::checkIsProcess64( HANDLE hProcess )
{
    BOOL bIsWow64 = FALSE;

    if ( !hProcess )
    {
        return PROCESS_MISSING_RIGHTS;
    }

    if ( !isWindows64( ) )
    {
        //32bit win can only run 32bit process
        return PROCESS_32;
    }

    ApiTools::IsWow64Process( hProcess, &bIsWow64 );

    if ( bIsWow64 == FALSE )
    {
        //process not running under wow
        return PROCESS_64;
    }

    //process running under wow -> 32bit
    return PROCESS_32;  
}

bool ProcessLister::getAbsoluteFilePath( HANDLE hProcess, Process* process ) {
    if ( !hProcess ) {
        // Missing rights or invalid handle.
        return false;
    }

    std::array<WCHAR, MAX_PATH> processPath{};
    wcscpy_s( process->fullPath, L"Unknown path" );

    //some virtual volumes
    if ( GetProcessImageFileNameW( hProcess, processPath.data( ), processPath.size( ) ) > 0 ) {

        if ( deviceNameResolver->resolveDeviceLongNameToShort( processPath.data( ), process->fullPath ) ) {
            return true; 
        }
        else {
            LOGS_DEBUG( "getAbsoluteFilePath :: resolveDeviceLongNameToShort failed with path %ls", processPath.data( ) );
        }
    }
    else {
        LOGS_DEBUG( "getAbsoluteFilePath :: GetProcessImageFileName failed %u", GetLastError( ) );
    }

    if ( GetModuleFileNameExW( hProcess, nullptr, process->fullPath, static_cast<DWORD>( sizeof( process->fullPath ) / 2 ) ) != 0 ) {
        return true;
    }

    return false;
}

static 
void* OldGetModuleBase( HANDLE hProcess, std::wstring ModName, size_t* Size )
{
    const auto strModName = Utils::StrToLower( ModName );

    static bool bFound = false;

    MEMORY_BASIC_INFORMATION mbi = { nullptr };

    uint8_t pBuff[ MAX_PATH * 2 + 4 ] = { 0 };

    bFound = false;

    auto Status = ApiTools::QueryVirtualMemory( hProcess, nullptr, MemoryBasicInformation, &mbi, sizeof mbi, nullptr );

    void* pInitBase = nullptr;

    for ( uint8_t* Address = nullptr; !ApiTools::QueryVirtualMemory( hProcess, Address, MemoryBasicInformation, &mbi, sizeof mbi, nullptr );
        Address = static_cast<uint8_t*>( mbi.BaseAddress ) + mbi.RegionSize )
    {
        if ( mbi.Type != MEM_IMAGE )
        {
            if ( bFound )
                return pInitBase;

            continue;
        }

        if ( ApiTools::QueryVirtualMemory( hProcess, mbi.BaseAddress, MemoryMappedFilenameInformation, pBuff, sizeof pBuff, nullptr ) )
            continue;

        auto* const pFullFile = reinterpret_cast<wchar_t*>( &pBuff[ 16 ] );

        if ( !pFullFile )
            continue;

        auto strFullFile = std::wstring( pFullFile );

        Utils::StrToLower( strFullFile );
        //if ( wcsstr( pFullFile, ModName ) != nullptr )

        if ( strFullFile.find( strModName ) != -1 )
        {
            bFound = true;

            if ( !Size )
                return mbi.BaseAddress;

            *Size += mbi.RegionSize;

            if ( !pInitBase )
                pInitBase = mbi.BaseAddress;
        }
        else
            if ( bFound )
                return pInitBase;
    }

    return nullptr;
}


std::vector<Process>& ProcessLister::getProcessListSnapshotNative( ) {

    if ( !processList.empty( ) ) {
        processList.clear( );
    }
    else {
        processList.reserve( 300 );
    }

    std::unique_ptr<void, VirtualFreeDeleter> buffer = ApiTools::GetSystemInfo( SystemProcessInformation );

    if ( !buffer ) {
        return processList;
    }

    PSYSTEM_PROCESSES_INFORMATION pIter = reinterpret_cast<PSYSTEM_PROCESSES_INFORMATION>( buffer.get( ) );

    while ( true ) {
        if ( reinterpret_cast<uintptr_t>( pIter->UniqueProcessId ) > 4 ) {
            handleProcessInformationAndAddToList( pIter );
        }

        if ( pIter->NextEntryDelta == 0 ) {
            break;
        }
        else {
            pIter = reinterpret_cast<PSYSTEM_PROCESSES_INFORMATION>( reinterpret_cast<uintptr_t>( pIter ) + pIter->NextEntryDelta );
        }
    }

    std::reverse( processList.begin( ), processList.end( ) );

    return processList;
}

void ProcessLister::handleProcessInformationAndAddToList( PSYSTEM_PROCESSES_INFORMATION pProcess )
{
    Process process{};

    WCHAR tempProcessName[ MAX_PATH * 2 ] = { 0 };

    process.PID = static_cast<DWORD>( reinterpret_cast<size_t>( pProcess->UniqueProcessId ) );

    HANDLE hProcess = ApiTools::OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.PID );

    if ( hProcess && hProcess != INVALID_HANDLE_VALUE )
    {
        ProcessType processType = checkIsProcess64( hProcess );

#ifdef _WIN64
        if ( processType == PROCESS_64 )
#else
        if ( processType == PROCESS_32 )
#endif
        {
            process.sessionId = pProcess->SessionId;

            memcpy( tempProcessName, pProcess->ImageName.Buffer, pProcess->ImageName.Length );
            wcscpy_s( process.filename, tempProcessName );

            getAbsoluteFilePath( hProcess, &process );

            process.pebAddress = getPebAddressFromProcess( hProcess );

            getProcessImageInformation( hProcess, &process );

            processList.push_back( process );
        }
        CloseHandle( hProcess );
    }
}

void ProcessLister::getProcessImageInformation( HANDLE hProcess, Process* process )
{
    DWORD_PTR readImagebase = 0;
    process->imageBase = 0;
    process->imageSize = 0;

    if ( hProcess && process->pebAddress )
    {
        PEB* peb = reinterpret_cast<PEB*>( process->pebAddress );

        if ( ApiTools::ReadProcessMemory( hProcess, &peb->ImageBaseAddress, &readImagebase, sizeof( DWORD_PTR ), 0 ) )
        {
            process->imageBase = readImagebase;
            process->imageSize = ProcessAccessHelp::getSizeOfImageProcess( hProcess, process->imageBase );
        }
    }
}

DWORD_PTR ProcessLister::getPebAddressFromProcess( HANDLE hProcess )
{
    if ( hProcess )
    {
        ULONG RequiredLen = 0;

        void* PebAddress = 0;

        PROCESS_BASIC_INFORMATION myProcessBasicInformation[ 5 ] = { 0 };

        if ( ApiTools::QueryInformationProcess( hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof( PROCESS_BASIC_INFORMATION ), &RequiredLen ) == STATUS_SUCCESS )
        {
            PebAddress = myProcessBasicInformation->PebBaseAddress;
        }
        else
        {
            if ( ApiTools::QueryInformationProcess( hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen ) == STATUS_SUCCESS )
            {
                PebAddress = myProcessBasicInformation->PebBaseAddress;
            }
        }

        return reinterpret_cast<DWORD_PTR>( PebAddress );
    }

    return 0;
}
