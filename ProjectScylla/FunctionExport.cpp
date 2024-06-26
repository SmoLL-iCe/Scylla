#include <windows.h>
#include "PeParser.h"
#include "ProcessAccessHelp.h"
#include "Architecture.h"
#include "FunctionExport.h"
#include "ProcessLister.h"
#include "ApiReader.h"
#include "IATSearch.h"
#include "ImportRebuilder.h"

BOOL DumpProcessW( const wchar_t* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const wchar_t* pFileResult )
{
	std::unique_ptr<PeParser> peFile{};

	( pFileToDump ) ?
		peFile->initializeFromFile( pFileToDump, true ) :
		peFile->initializeFromProcess( uImageBase, true );

	return peFile->dumpProcess( uImageBase, uEntrypoint, pFileResult );
}

BOOL WINAPI ScyllaRebuildFileW( const wchar_t* pFileToRebuild, BOOL bRemoveDosStub, BOOL bUpdatePeHeaderChecksum, BOOL bCreateBackup )
{
	if ( bCreateBackup )
	{
		if ( !ProcessAccessHelp::createBackupFile( pFileToRebuild ) )
		{
			return FALSE;
		}
	}

	std::unique_ptr<PeParser> peFile = std::make_unique<PeParser>( pFileToRebuild, true );

	if ( peFile->readPeSectionsFromFile( ) )
	{
		peFile->setDefaultFileAlignment( );

		if ( bRemoveDosStub )
		{
			peFile->removeDosStub( );
		}

		peFile->alignAllSectionHeaders( );

		peFile->fixPeHeader( );

		if ( peFile->savePeFileToDisk( pFileToRebuild ) )
		{
			if ( bUpdatePeHeaderChecksum )
			{
				PeParser::updatePeHeaderChecksum( pFileToRebuild, ProcessAccessHelp::getFileSize( pFileToRebuild ) );
			}
			return TRUE;
		}
	}

	return FALSE;
}

BOOL WINAPI ScyllaRebuildFileA( const char* pFileToRebuild, BOOL bRemoveDosStub, BOOL bUpdatePeHeaderChecksum, BOOL bCreateBackup )
{
	wchar_t fileToRebuildW[ MAX_PATH ]{ };

	if ( MultiByteToWideChar( CP_ACP, 0, pFileToRebuild, -1, fileToRebuildW, _countof( fileToRebuildW ) ) == 0 )
	{
		return FALSE;
	}

	return ScyllaRebuildFileW( fileToRebuildW, bRemoveDosStub, bUpdatePeHeaderChecksum, bCreateBackup );
}

BOOL WINAPI ScyllaDumpCurrentProcessW( const wchar_t* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const wchar_t* pFileResult )
{
	ProcessAccessHelp::setCurrentProcessAsTarget( );

	return DumpProcessW( pFileToDump, uImageBase, uEntrypoint, pFileResult );
}

BOOL WINAPI ScyllaDumpProcessW( std::uintptr_t pid, const wchar_t* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const wchar_t* pFileResult )
{
	if ( ProcessAccessHelp::openProcessHandle( (std::uint32_t)pid ) )
	{
		return DumpProcessW( pFileToDump, uImageBase, uEntrypoint, pFileResult );
	}

	return FALSE;
}

BOOL WINAPI ScyllaDumpCurrentProcessA( const char* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const char* pFileResult )
{
	wchar_t fileToDumpW[ MAX_PATH ]{ };
	wchar_t fileResultW[ MAX_PATH ]{ };

	if ( pFileResult == 0 )
	{
		return FALSE;
	}

	if ( MultiByteToWideChar( CP_ACP, 0, pFileResult, -1, fileResultW, _countof( fileResultW ) ) == 0 )
	{
		return FALSE;
	}

	if ( pFileToDump != 0 )
	{
		if ( MultiByteToWideChar( CP_ACP, 0, pFileToDump, -1, fileToDumpW, _countof( fileToDumpW ) ) == 0 )
		{
			return FALSE;
		}

		return ScyllaDumpCurrentProcessW( fileToDumpW, uImageBase, uEntrypoint, fileResultW );
	}

	return ScyllaDumpCurrentProcessW( 0, uImageBase, uEntrypoint, fileResultW );
}

BOOL WINAPI ScyllaDumpProcessA( std::uintptr_t pid, const char* pFileToDump, std::uintptr_t uImageBase, std::uintptr_t uEntrypoint, const char* pFileResult )
{
	wchar_t fileToDumpW[ MAX_PATH ];
	wchar_t fileResultW[ MAX_PATH ];

	if ( pFileResult == 0 )
	{
		return FALSE;
	}

	if ( MultiByteToWideChar( CP_ACP, 0, pFileResult, -1, fileResultW, _countof( fileResultW ) ) == 0 )
	{
		return FALSE;
	}

	if ( pFileToDump != 0 )
	{
		if ( MultiByteToWideChar( CP_ACP, 0, pFileToDump, -1, fileToDumpW, _countof( fileToDumpW ) ) == 0 )
		{
			return FALSE;
		}

		return ScyllaDumpProcessW( pid, fileToDumpW, uImageBase, uEntrypoint, fileResultW );
	}

	return ScyllaDumpProcessW( pid, 0, uImageBase, uEntrypoint, fileResultW );	
}

int WINAPI ScyllaIatSearch( std::uint32_t uProcessId, std::uintptr_t* pIatStart, std::uint32_t* pIatSize, std::uintptr_t uSearchStart, BOOL bAdvancedSearch )
{
	ApiReader apiReader{ };

	ProcessLister processLister{};

	Process currentProcess = {};

	IATSearch iatSearch{};

	std::vector<Process>& vProcessList = processLister.getProcessListSnapshotNative( );

	for ( const auto& Proc : vProcessList )
	{
		if ( Proc.PID == uProcessId )
		{
			currentProcess = Proc;
			break;
		}
	}

	if ( !currentProcess.PID )
		return SCY_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle( );

	apiReader.clearAll( );

	if ( !ProcessAccessHelp::openProcessHandle( currentProcess.PID ) )
	{
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::vModuleList );

	ProcessAccessHelp::uTargetImageBase = currentProcess.uImageBase;

	ProcessAccessHelp::uTargetSizeOfImage = currentProcess.uImageSize;

	apiReader.readApisFromModuleList( );

	int retVal = SCY_ERROR_IATNOTFOUND;

	if ( bAdvancedSearch )
	{
		if ( iatSearch.searchImportAddressTableInProcess( uSearchStart, pIatStart, pIatSize, true ) )
		{
			retVal = SCY_ERROR_SUCCESS;
		}
	}
	else
	{
		if ( iatSearch.searchImportAddressTableInProcess( uSearchStart, pIatStart, pIatSize, false ) )
		{
			retVal = SCY_ERROR_SUCCESS;
		}
	}

	vProcessList.clear( );

	ProcessAccessHelp::closeProcessHandle( );

	apiReader.clearAll( );

	return retVal;
}

int WINAPI ScyllaIatFixAutoW( std::uintptr_t uIatAddr, std::uint32_t uIatSize, std::uint32_t uProcessId, const wchar_t* pDumpFile, const wchar_t* pIatFixFile )
{
	ApiReader apiReader{};

	ProcessLister processLister{};

	Process currentProcess{};

	std::map<std::uintptr_t, ImportModuleThunk> vModuleList;

	std::vector<Process>& vProcessList = processLister.getProcessListSnapshotNative( );

	for ( const auto& Proc : vProcessList )
	{
		if ( Proc.PID == uProcessId )
		{
			currentProcess = Proc;
			break;
		}
	}

	if ( !currentProcess.PID )
		return SCY_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle( );

	apiReader.clearAll( );

	if ( !ProcessAccessHelp::openProcessHandle( currentProcess.PID ) )
	{
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::vModuleList );

	ProcessAccessHelp::uTargetImageBase = currentProcess.uImageBase;

	ProcessAccessHelp::uTargetSizeOfImage = currentProcess.uImageSize;

	apiReader.readApisFromModuleList( );

	apiReader.readAndParseIAT( uIatAddr, uIatSize, vModuleList );

	//add IAT section to dump
	ImportRebuilder importRebuild( pDumpFile );

	importRebuild.enableOFTSupport( );

	int retVal = SCY_ERROR_IATWRITE;

	if ( importRebuild.rebuildImportTable( pIatFixFile, vModuleList ) )
	{
		retVal = SCY_ERROR_SUCCESS;
	}

	vProcessList.clear( );

	vModuleList.clear( );

	ProcessAccessHelp::closeProcessHandle( );

	apiReader.clearAll( );

	return retVal;
}
