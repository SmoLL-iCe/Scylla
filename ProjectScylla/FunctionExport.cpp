#include <windows.h>
#include "PeParser.h"
#include "ProcessAccessHelp.h"
#include "Architecture.h"
#include "FunctionExport.h"
#include "ProcessLister.h"
#include "ApiReader.h"
#include "IATSearch.h"
#include "ImportRebuilder.h"

BOOL DumpProcessW( const wchar_t* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const wchar_t* fileResult )
{
	PeParser* peFile = 0;

	if ( fileToDump )
	{
		peFile = new PeParser( fileToDump, true );
	}
	else
	{
		peFile = new PeParser( imagebase, true );
	}

	bool result = peFile->dumpProcess( imagebase, entrypoint, fileResult );

	delete peFile;
	return result;
}

BOOL WINAPI ScyllaRebuildFileW( const wchar_t* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup )
{
	if ( createBackup )
	{
		if ( !ProcessAccessHelp::createBackupFile( fileToRebuild ) )
		{
			return FALSE;
		}
	}

	PeParser peFile( fileToRebuild, true );
	if ( peFile.readPeSectionsFromFile( ) )
	{
		peFile.setDefaultFileAlignment( );
		if ( removeDosStub )
		{
			peFile.removeDosStub( );
		}
		peFile.alignAllSectionHeaders( );
		peFile.fixPeHeader( );

		if ( peFile.savePeFileToDisk( fileToRebuild ) )
		{
			if ( updatePeHeaderChecksum )
			{
				PeParser::updatePeHeaderChecksum( fileToRebuild, ProcessAccessHelp::getFileSize( fileToRebuild ) );
			}
			return TRUE;
		}
	}

	return FALSE;
}

BOOL WINAPI ScyllaRebuildFileA( const char* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup )
{
	wchar_t fileToRebuildW[ MAX_PATH ];
	if ( MultiByteToWideChar( CP_ACP, 0, fileToRebuild, -1, fileToRebuildW, _countof( fileToRebuildW ) ) == 0 )
	{
		return FALSE;
	}

	return ScyllaRebuildFileW( fileToRebuildW, removeDosStub, updatePeHeaderChecksum, createBackup );
}

BOOL WINAPI ScyllaDumpCurrentProcessW( const wchar_t* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const wchar_t* fileResult )
{
	ProcessAccessHelp::setCurrentProcessAsTarget( );

	return DumpProcessW( fileToDump, imagebase, entrypoint, fileResult );
}

BOOL WINAPI ScyllaDumpProcessW( std::uintptr_t pid, const wchar_t* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const wchar_t* fileResult )
{
	if ( ProcessAccessHelp::openProcessHandle( (std::uint32_t)pid ) )
	{
		return DumpProcessW( fileToDump, imagebase, entrypoint, fileResult );
	}
	else
	{
		return FALSE;
	}
}

BOOL WINAPI ScyllaDumpCurrentProcessA( const char* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const char* fileResult )
{
	wchar_t fileToDumpW[ MAX_PATH ];
	wchar_t fileResultW[ MAX_PATH ];

	if ( fileResult == 0 )
	{
		return FALSE;
	}

	if ( MultiByteToWideChar( CP_ACP, 0, fileResult, -1, fileResultW, _countof( fileResultW ) ) == 0 )
	{
		return FALSE;
	}

	if ( fileToDump != 0 )
	{
		if ( MultiByteToWideChar( CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof( fileToDumpW ) ) == 0 )
		{
			return FALSE;
		}

		return ScyllaDumpCurrentProcessW( fileToDumpW, imagebase, entrypoint, fileResultW );
	}
	else
	{
		return ScyllaDumpCurrentProcessW( 0, imagebase, entrypoint, fileResultW );
	}
}

BOOL WINAPI ScyllaDumpProcessA( std::uintptr_t pid, const char* fileToDump, std::uintptr_t imagebase, std::uintptr_t entrypoint, const char* fileResult )
{
	wchar_t fileToDumpW[ MAX_PATH ];
	wchar_t fileResultW[ MAX_PATH ];

	if ( fileResult == 0 )
	{
		return FALSE;
	}

	if ( MultiByteToWideChar( CP_ACP, 0, fileResult, -1, fileResultW, _countof( fileResultW ) ) == 0 )
	{
		return FALSE;
	}

	if ( fileToDump != 0 )
	{
		if ( MultiByteToWideChar( CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof( fileToDumpW ) ) == 0 )
		{
			return FALSE;
		}

		return ScyllaDumpProcessW( pid, fileToDumpW, imagebase, entrypoint, fileResultW );
	}
	else
	{
		return ScyllaDumpProcessW( pid, 0, imagebase, entrypoint, fileResultW );
	}
}

int WINAPI ScyllaIatSearch( std::uint32_t dwProcessId, std::uintptr_t* iatStart, std::uint32_t* pIatSize, std::uintptr_t searchStart, BOOL advancedSearch )
{
	ApiReader apiReader;
	ProcessLister processLister;
	Process* processPtr = 0;
	IATSearch iatSearch;

	std::vector<Process>& vProcessList = processLister.getProcessListSnapshotNative( );
	for ( std::vector<Process>::iterator it = vProcessList.begin( ); it != vProcessList.end( ); ++it )
	{
		if ( it->PID == dwProcessId )
		{
			processPtr = &( *it );
			break;
		}
	}

	if ( !processPtr )
		return SCY_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle( );
	apiReader.clearAll( );

	if ( !ProcessAccessHelp::openProcessHandle( processPtr->PID ) )
	{
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::vModuleList );

	//ProcessAccessHelp::selectedModule = 0;
	ProcessAccessHelp::uTargetImageBase = processPtr->uImageBase;
	ProcessAccessHelp::uTargetSizeOfImage = processPtr->uImageSize;

	apiReader.readApisFromModuleList( );

	int retVal = SCY_ERROR_IATNOTFOUND;

	if ( advancedSearch )
	{
		if ( iatSearch.searchImportAddressTableInProcess( searchStart, iatStart, pIatSize, true ) )
		{
			retVal = SCY_ERROR_SUCCESS;
		}
	}
	else
	{
		if ( iatSearch.searchImportAddressTableInProcess( searchStart, iatStart, pIatSize, false ) )
		{
			retVal = SCY_ERROR_SUCCESS;
		}
	}

	vProcessList.clear( );
	ProcessAccessHelp::closeProcessHandle( );
	apiReader.clearAll( );

	return retVal;
}


int WINAPI ScyllaIatFixAutoW( std::uintptr_t iatAddr, std::uint32_t pIatSize, std::uint32_t dwProcessId, const wchar_t* dumpFile, const wchar_t* iatFixFile )
{
	ApiReader apiReader;
	ProcessLister processLister;
	Process* processPtr = 0;
	std::map<std::uintptr_t, ImportModuleThunk> vModuleList;

	std::vector<Process>& vProcessList = processLister.getProcessListSnapshotNative( );
	for ( std::vector<Process>::iterator it = vProcessList.begin( ); it != vProcessList.end( ); ++it )
	{
		if ( it->PID == dwProcessId )
		{
			processPtr = &( *it );
			break;
		}
	}

	if ( !processPtr )
		return SCY_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle( );
	apiReader.clearAll( );

	if ( !ProcessAccessHelp::openProcessHandle( processPtr->PID ) )
	{
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::vModuleList );

	//ProcessAccessHelp::selectedModule = 0;
	ProcessAccessHelp::uTargetImageBase = processPtr->uImageBase;
	ProcessAccessHelp::uTargetSizeOfImage = processPtr->uImageSize;

	apiReader.readApisFromModuleList( );

	apiReader.readAndParseIAT( iatAddr, pIatSize, vModuleList );

	//add IAT section to dump
	ImportRebuilder importRebuild( dumpFile );
	importRebuild.enableOFTSupport( );

	int retVal = SCY_ERROR_IATWRITE;

	if ( importRebuild.rebuildImportTable( iatFixFile, vModuleList ) )
	{
		retVal = SCY_ERROR_SUCCESS;
	}

	vProcessList.clear( );
	vModuleList.clear( );
	ProcessAccessHelp::closeProcessHandle( );
	apiReader.clearAll( );

	return retVal;
}
