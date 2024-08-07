#include "ProcessLister.h"
#include "SystemInformation.h"
#include "Logger.h"
#include "ProcessAccessHelp.h"
#include <algorithm>
#include "Tools/Logs.h"
#include "WinApi/ApiRemote.h"
#include <array> 
#include "Tools/Utils.h"
#include "WinApi/RemoteModule.h"

std::vector<Process>& ProcessLister::getProcessList( )
{
    return vProcessList;
}

bool ProcessLister::isWindows64( )
{
#ifdef WIN64
    //compiled 64bit application
    return true;
#else
    BOOL bIsWow64 = FALSE;

    ApiRemote::IsWow64Process( reinterpret_cast<HANDLE>( -1 ), &bIsWow64 );

    return ( bIsWow64 != FALSE );
#endif
}

std::uint32_t ProcessLister::setDebugPrivileges( )
{
    std::uint32_t uErr = 0;
    HANDLE hToken = 0;
    TOKEN_PRIVILEGES Debug_Privileges = { 0 };

    if ( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[ 0 ].Luid ) )
    {
        return GetLastError( );
    }

    if ( !OpenProcessToken( reinterpret_cast<HANDLE>( -1 ), TOKEN_ADJUST_PRIVILEGES, &hToken ) )
    {
        uErr = GetLastError( );
        if ( hToken ) CloseHandle( hToken );
        return uErr;
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

    ApiRemote::IsWow64Process( hProcess, &bIsWow64 );

    if ( bIsWow64 == FALSE )
    {
        //process not running under wow
        return PROCESS_64;
    }

    //process running under wow -> 32bit
    return PROCESS_32;
}

bool ProcessLister::getAbsoluteFilePath( HANDLE hProcess, Process* pProcess ) {
    if ( !hProcess ) {
        // Missing rights or invalid handle.
        return false;
    }

    std::wstring strFullPath = RemoteModule::GetFullModulePathFromBase(
        hProcess, 
        reinterpret_cast<HMODULE>( pProcess->uImageBase ),
        pProcess->archType == PROCESS_64
    );

    wcscpy_s( pProcess->pModulePath, L"Unknown path" );

    if ( strFullPath.empty( ) )
        return false;

    wcscpy_s( pProcess->pModulePath, strFullPath.data( ) );

	return true;
}

std::vector<Process>& ProcessLister::getProcessListSnapshotNative( ) {

    if ( !vProcessList.empty( ) ) {
        vProcessList.clear( );
    }
    else {
        vProcessList.reserve( 300 );
    }

    std::unique_ptr<void, VirtualFreeDeleter> pBuffer = ApiRemote::GetSystemInfo( SystemProcessInformation );

    if ( !pBuffer ) {
        return vProcessList;
    }

    PSYSTEM_PROCESSES_INFORMATION pIter = reinterpret_cast<PSYSTEM_PROCESSES_INFORMATION>( pBuffer.get( ) );

    while ( true ) {
        if ( reinterpret_cast<uintptr_t>( pIter->UniqueProcessId ) > 4 ) {
            handleProcessInformationAndAddToList( pIter );
        }

        if ( pIter->NextEntryDelta == 0 ) {
            break;
        } else {
            pIter = reinterpret_cast<PSYSTEM_PROCESSES_INFORMATION>( reinterpret_cast<uintptr_t>( pIter ) + pIter->NextEntryDelta );
        }
    }

    std::reverse( vProcessList.begin( ), vProcessList.end( ) );

    return vProcessList;
}

void ProcessLister::handleProcessInformationAndAddToList( PSYSTEM_PROCESSES_INFORMATION pProcess )
{
    Process process {};

    wchar_t tempProcessName[ MAX_PATH * 2 ] = { 0 };

    process.PID = static_cast<std::uint32_t>( reinterpret_cast<std::size_t>( pProcess->UniqueProcessId ) );

    HANDLE hProcess = ApiRemote::OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.PID );

    if ( hProcess && hProcess != INVALID_HANDLE_VALUE )
    {
        process.archType = checkIsProcess64( hProcess );

#ifdef WIN64
        if ( process.archType == PROCESS_64 || process.archType == PROCESS_32 )
#else
        if ( process.archType == PROCESS_32 )
#endif
        {
            process.uSessionId = pProcess->SessionId;

            memcpy( tempProcessName, pProcess->ImageName.Buffer, pProcess->ImageName.Length );
            wcscpy_s( process.pFileName, tempProcessName );

            getAbsoluteFilePath( hProcess, &process );

            process.uPebAddress = getPebAddressFromProcess( hProcess, process.archType );

            getProcessImageInformation( hProcess, &process );

            vProcessList.push_back( process );
        }
        CloseHandle( hProcess );
    }
}

void ProcessLister::getProcessImageInformation( HANDLE hProcess, Process* pProcess )
{
    std::uintptr_t uReadImagebase = 0;

    pProcess->uImageBase = 0;
    //pProcess->uImageSize = 0;

    if ( hProcess && pProcess->uPebAddress )
    {
        PEB* peb = reinterpret_cast<PEB*>( pProcess->uPebAddress );

        if ( ApiRemote::ReadProcessMemory( hProcess, &peb->ImageBaseAddress, &uReadImagebase, sizeof( std::uintptr_t ), 0 ) )
        {
            pProcess->uImageBase = uReadImagebase;
            pProcess->uImageSize = ProcessAccessHelp::getSizeOfImageProcess( hProcess, pProcess->uImageBase );
        }
    }
}

std::uintptr_t ProcessLister::getPebAddressFromProcess( HANDLE hProcess, ProcessType archType )
{
    return reinterpret_cast<std::uintptr_t>( RemoteModule::GetProcessPeb( hProcess, archType == PROCESS_64 ) );
}
