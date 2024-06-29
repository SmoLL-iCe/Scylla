#include "ScyllaContext.h"
#include "PeParser.h"
#include "Architecture.h"
#include "FunctionExport.h"
#include "ScyllaConfig.hpp"
#include "IATSearch.h"
#include "ImportRebuilder.h"


#define Logs(fmt, ...) printf( fmt, __VA_ARGS__)

static bool isFileExists( const std::wstring& strFilename )
{
	std::uint32_t dwAttrib = GetFileAttributes( strFilename.c_str( ) );

	return ( dwAttrib != INVALID_FILE_ATTRIBUTES && !( dwAttrib & FILE_ATTRIBUTE_DIRECTORY ) );
}

static
std::wstring getCurrentDirectory( )
{
	wchar_t pBuffer[ MAX_PATH ] = { 0 };

	GetCurrentDirectory( MAX_PATH, pBuffer );

	return std::wstring( pBuffer );
}

ScyllaContext::ScyllaContext( const std::wstring& strProcessName )
{
	std::vector<Process>& vProcessList = m_processLister.getProcessListSnapshotNative( );

	std::uint32_t uProcessId = 0;

	for ( auto& vProcess : vProcessList )
	{
		if ( std::wstring( vProcess.pFileName ).find( strProcessName ) != std::wstring::npos )
		{
			uProcessId = vProcess.PID;
			break;
		}
	}

	Status = ScyllaContext::setProcessById( uProcessId );
}

ScyllaContext::ScyllaContext( std::uint32_t uProcessId )
{
	Status = ScyllaContext::setProcessById( uProcessId );
}

ScyllaContext::~ScyllaContext( ) {}

void ScyllaContext::getPePreInfo( )
{
	if ( m_strDumpFullFilePath.empty( ) && !ProcessAccessHelp::uTargetImageBase )
		return;

	PeParser* pPeFile = ( Config::USE_PE_HEADER_FROM_DISK && !m_strDumpFullFilePath.empty( ) ) ?
		new PeParser( m_strTargetFilePath.c_str( ), false ) :
		new PeParser( ProcessAccessHelp::uTargetImageBase, false );

	m_entrypoint = pPeFile->getEntryPoint( ) + m_processPtr.uImageBase;

	auto pDirImport = pPeFile->getDirectory( IMAGE_DIRECTORY_ENTRY_IAT );

	if ( pDirImport )
	{
		std::uintptr_t uAddressIAT = pDirImport->VirtualAddress;
		std::uint32_t uSizeIAT = pDirImport->Size;

		if ( uAddressIAT && uSizeIAT )
		{
			m_addressIAT = uAddressIAT + m_processPtr.uImageBase;
			m_sizeIAT = uSizeIAT;
		}
	}

	if ( !ProcessAccessHelp::uTargetSizeOfImage )
	{
		ProcessAccessHelp::uTargetSizeOfImage = pPeFile->getCurrentNtHeader( )->OptionalHeader.SizeOfImage;
	}
}

int ScyllaContext::setProcessById( std::uint32_t uProcessId ) {

	if ( !uProcessId )
	{
		Logs( "%s Process ID not found\n", __FUNCTION__ );
		return SCY_ERROR_PIDNOTFOUND;
	}

	std::vector<Process>& vProcessList = m_processLister.getProcessListSnapshotNative( );

	for ( auto& vProcess : vProcessList )
	{
		if ( vProcess.PID == uProcessId )
		{
			m_processPtr = vProcess;
			break;
		}
	}

	vProcessList.clear( );

	if ( !m_processPtr.PID )
	{
		Logs( "%s Process ID not found 2\n", __FUNCTION__ );
		return SCY_ERROR_PIDNOTFOUND;
	}

	ProcessAccessHelp::closeProcessHandle( );

	m_apiReader.clearAll( );

	if ( !ProcessAccessHelp::openProcessHandle( m_processPtr.PID ) )
	{
		Logs( "%s failed to open process\n", __FUNCTION__ );
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::uTargetImageBase = m_processPtr.uImageBase;

	ProcessAccessHelp::uTargetSizeOfImage = m_processPtr.uImageSize;

	m_strTargetFilePath = m_processPtr.pModulePath;

	getPePreInfo( );

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::vModuleList );

	m_apiReader.readApisFromModuleList( );

	Logs( "%s Loading modules done.\n", __FUNCTION__ );

	Logs( "%s Imagebase: " PRINTF_DWORD_PTR_FULL_S " Size: %08X\n", __FUNCTION__, m_processPtr.uImageBase, m_processPtr.uImageSize );

	getCurrentDefaultDumpFilename( );

	m_bIsModule = false;

	return SCY_ERROR_SUCCESS;
}

bool ScyllaContext::setTargetModule( const std::wstring& strModuleName ) {

	if ( !ProcessAccessHelp::hProcess )
	{
		return false;
	}

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::vModuleList );

	if ( ProcessAccessHelp::vModuleList.empty( ) )
	{
		Logs( "%s failed to list modules\n", __FUNCTION__ );
		return false;
	}

	for ( auto& pModuleInfo : ProcessAccessHelp::vModuleList )
	{
		if ( std::wstring( pModuleInfo.pModulePath ).find( strModuleName ) != std::wstring::npos )
		{
			return setTargetModule( pModuleInfo.uModBase, pModuleInfo.uModBaseSize, pModuleInfo.pModulePath );
		}
	}

	return false;
}

bool ScyllaContext::setTargetModule( std::uintptr_t uBaseModule ) {

	if ( !ProcessAccessHelp::hProcess )
		return false;

	return setTargetModule( uBaseModule, 0, L"NoPath\\NoModule" );
}

bool ScyllaContext::setTargetModule( std::uintptr_t uBaseModule, std::uintptr_t uModuleSize, const std::wstring& strModulePath ) {

	if ( !ProcessAccessHelp::hProcess )
		return false;

	Logs( "%s setTargetModule %ls\n", __FUNCTION__, strModulePath.c_str( ) );

	if ( ProcessAccessHelp::vModuleList.empty( ) )
	{
		Logs( "%s failed to list modules\n", __FUNCTION__ );
		return false;
	}

	if ( m_processPtr.uImageBase != uBaseModule )
	{
		ProcessAccessHelp::uTargetImageBase = uBaseModule;

		ProcessAccessHelp::uTargetSizeOfImage = uModuleSize ;

		m_strTargetFilePath = strModulePath;
	}

	getPePreInfo( );

	getCurrentDefaultDumpFilename( );

	m_bIsModule = true;

	return true;
}

bool ScyllaContext::isIATOutsidePeImage( std::uintptr_t uAddressIAT ) const
{
	std::uintptr_t minAdd = ProcessAccessHelp::uTargetImageBase;
	std::uintptr_t maxAdd = minAdd + ProcessAccessHelp::uTargetSizeOfImage;
	return !( uAddressIAT > minAdd && uAddressIAT < maxAdd );
}

void ScyllaContext::checkSuspendProcess( )
{
	if ( Config::SUSPEND_PROCESS_FOR_DUMPING )
	{
		if ( !ProcessAccessHelp::suspendProcess( ) )
		{
			Logs( "%s Error: Cannot suspend process.\n", __FUNCTION__ );
		}
		else
		{
			m_isProcessSuspended = true;
			Logs( "%s Suspending process successful, please resume manually.\n", __FUNCTION__ );
		}
	}
}

bool ScyllaContext::getCurrentDefaultDumpFilename( )
{
	if ( !m_processPtr.PID )
		return false;

	if ( !isFileExists( m_strTargetFilePath ) )
	{
		auto currrentDir = getCurrentDirectory( );

		m_strDumpFullFilePath = currrentDir + ( ( m_bIsModule ) ? L"\\dump.dll" : L"\\dump.exe" );
		m_strDumpFullFilePathScy = currrentDir + ( ( m_bIsModule ) ? L"\\dump_SCY.dll" : L"\\dump_SCY.exe" );

		return true;
	}

	auto lastSlashPos = m_strTargetFilePath.find_last_of( L'\\' );

	if ( lastSlashPos != std::wstring::npos ) {

		std::wstring pFileName = m_strTargetFilePath.substr( lastSlashPos + 1 );

		auto lastDotPos = pFileName.find_last_of( L'.' );

		if ( lastDotPos != std::wstring::npos ) {

			pFileName = m_strTargetFilePath.substr( 0, lastSlashPos + 1 ) + pFileName.substr( 0, lastDotPos );

			m_strDumpFullFilePath = pFileName + ( ( m_bIsModule ) ? L"_dump.dll" : L"_dump.exe" );
			m_strDumpFullFilePathScy = pFileName + ( ( m_bIsModule ) ? L"_dump_SCY.dll" : L"_dump_SCY.exe" );

			return true;
		}
	}

	return false;
}

bool ScyllaContext::getCurrentModulePath( std::wstring& outModulePath ) const {

	if ( !m_processPtr.PID )
		return false;

	outModulePath = m_strTargetFilePath;

	if ( !isFileExists( outModulePath ) )
	{
		outModulePath = getCurrentDirectory( ) + L"\\";

		return true;
	}

	auto slashPos = outModulePath.find_last_of( L'\\' );

	if ( slashPos != std::wstring::npos ) {

		outModulePath = outModulePath.substr( 0, slashPos + 1 );
	}

	return true;
}

void ScyllaContext::dumpActionHandler( )
{
	if ( !m_processPtr.PID )
		return;

	checkSuspendProcess( );

	PeParser* pPeFile = ( Config::USE_PE_HEADER_FROM_DISK ) ?
		new PeParser( m_strTargetFilePath.c_str( ), true ) :
		new PeParser( ProcessAccessHelp::uTargetImageBase, true );

	if ( pPeFile->isValidPeFile( ) )
	{
		if ( pPeFile->dumpProcess( ProcessAccessHelp::uTargetImageBase, m_entrypoint, m_strDumpFullFilePath.c_str( ) ) )
		{
			Logs( "%s Dump success %ls\n", __FUNCTION__, m_strDumpFullFilePath.c_str( ) );
		}
		else
		{
			Logs( "%s Error: Cannot dump image.\n", __FUNCTION__ );
			MessageBox( 0, L"Cannot dump image.", L"Failure", MB_ICONERROR );
		}
	}
	else
	{
		Logs( "%s Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process.\n", __FUNCTION__ );
	}

	delete pPeFile;
}


void ScyllaContext::peRebuildActionHandler( )
{
	std::uint32_t newSize = 0;
	//wchar_t selectedFilePath[ MAX_PATH ];

	//getCurrentModulePath( stringBuffer, _countof( stringBuffer ) );
	//if ( showFileDialog( selectedFilePath, false, NULL, filterExeDll, NULL, stringBuffer ) )
	{
		if ( Config::CREATE_BACKUP )
		{
			if ( !ProcessAccessHelp::createBackupFile( m_strDumpFullFilePath.c_str( ) ) )
			{
				Logs( "%s Creating backup file failed %ls\n", __FUNCTION__, m_strDumpFullFilePath.c_str( ) );
			}
		}

		std::uint32_t uFileSize = ProcessAccessHelp::getFileSize( m_strDumpFullFilePath.c_str( ) );

		PeParser peFile( m_strDumpFullFilePath.c_str( ), true );

		if ( !peFile.isValidPeFile( ) )
		{
			Logs( "%s This is not a valid PE file %ls\n", __FUNCTION__, m_strDumpFullFilePath.c_str( ) );

			MessageBox( 0, L"Not a valid PE file.", L"Failure", MB_ICONERROR );
			return;
		}

		if ( peFile.readPeSectionsFromFile( ) )
		{
			peFile.setDefaultFileAlignment( );

			if ( Config::REMOVE_DOS_HEADER_STUB )
			{
				peFile.removeDosStub( );
			}

			peFile.alignAllSectionHeaders( );
			peFile.fixPeHeader( );

			if ( peFile.savePeFileToDisk( m_strDumpFullFilePath.c_str( ) ) )
			{
				newSize = ProcessAccessHelp::getFileSize( m_strDumpFullFilePath.c_str( ) );

				if ( Config::UPDATE_HEADER_CHECKSUM )
				{
					Logs( "%s Generating PE header checksum\n", __FUNCTION__ );

					if ( !PeParser::updatePeHeaderChecksum( m_strDumpFullFilePath.c_str( ), newSize ) )
					{
						Logs( "%s Generating PE header checksum FAILED!\n", __FUNCTION__ );
					}
				}

				Logs( "%s Rebuild success %ls\n", __FUNCTION__, m_strDumpFullFilePath.c_str( ) );
				Logs( "%s -> Old file size 0x%08X new file size 0x%08X (%d %%)\n", __FUNCTION__, uFileSize, newSize, ( ( newSize * 100 ) / uFileSize ) );
			}
			else
			{
				Logs( "%s Rebuild failed, cannot save file %ls\n", __FUNCTION__, m_strDumpFullFilePath.c_str( ) );
				MessageBox( 0, L"Rebuild failed. Cannot save file.", L"Failure", MB_ICONERROR );
			}
		}
		else
		{
			Logs( "%s Rebuild failed, cannot read file %ls\n", __FUNCTION__, m_strDumpFullFilePath.c_str( ) );
			MessageBox( 0, L"Rebuild failed. Cannot read file.", L"Failure", MB_ICONERROR );
		}

	}
}

void ScyllaContext::dumpFixActionHandler( )
{
	if ( !m_processPtr.PID )
		return;

	ImportRebuilder importRebuild( m_strDumpFullFilePath.c_str( ) );

	if ( Config::IAT_FIX_AND_OEP_FIX )
	{
		importRebuild.setEntryPointRva( static_cast<std::uint32_t>( m_entrypoint - ProcessAccessHelp::uTargetImageBase ) );
	}

	if ( Config::OriginalFirstThunk_SUPPORT )
	{
		importRebuild.enableOFTSupport( );
	}

	if ( Config::SCAN_DIRECT_IMPORTS && Config::FIX_DIRECT_IMPORTS_UNIVERSAL )
	{
		if ( m_iatReferenceScan.numberOfFoundDirectImports( ) > 0 )
		{
			importRebuild.pIatReferenceScan = &m_iatReferenceScan;
			importRebuild.bBuildDirectImportsJumpTable = true;
		}
	}

	if ( Config::CREATE_NEW_IAT_IN_SECTION )
	{
		importRebuild.pIatReferenceScan = &m_iatReferenceScan;

		std::uintptr_t uAddressIAT = m_addressIAT;
		std::uint32_t uSizeIAT = m_sizeIAT;

		importRebuild.enableNewIatInSection( uAddressIAT, uSizeIAT );
	}

	if ( importRebuild.rebuildImportTable( this->m_strDumpFullFilePathScy.c_str( ), m_importsHandling.vModuleList ) )
	{
		Logs( "%s Import Rebuild success %ls\n", __FUNCTION__, this->m_strDumpFullFilePathScy.c_str( ) );
	}
	else
	{
		Logs( "%s Import Rebuild failed %ls\n", __FUNCTION__, m_strDumpFullFilePath.c_str( ) );
		MessageBox( 0, L"Import Rebuild failed", L"Failure", MB_ICONERROR );
	}

}

void ScyllaContext::setDialogIATAddressAndSize( std::uintptr_t uAddressIAT, std::uint32_t uSizeIAT )
{
	m_addressIAT = uAddressIAT;
	m_sizeIAT = uSizeIAT;

	wchar_t stringBuffer[ 256 ] = { 0 };

	swprintf_s( stringBuffer, L"IAT found:\r\n\r\nStart: " PRINTF_DWORD_PTR_FULL L"\r\nSize: 0x%04X (%d) ", uAddressIAT, uSizeIAT, uSizeIAT );
	MessageBox( 0, stringBuffer, L"IAT found", MB_ICONINFORMATION );
}

void ScyllaContext::iatAutosearchActionHandler( )
{
	std::uintptr_t searchAddress = m_entrypoint;
	std::uintptr_t uAddressIAT = 0, addressIATAdv = 0;
	std::uint32_t uSizeIAT = 0, sizeIATAdv = 0;
	IATSearch iatSearch { };

	if ( !m_processPtr.PID )
		return;

	if ( searchAddress )
	{

		if ( Config::USE_ADVANCED_IAT_SEARCH )
		{
			if ( iatSearch.searchImportAddressTableInProcess( searchAddress, &addressIATAdv, &sizeIATAdv, true ) )
			{
				Logs( "%s IAT Search Adv: IAT VA " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " Size 0x%04X (%d)\n", __FUNCTION__,
					addressIATAdv, addressIATAdv - ProcessAccessHelp::uTargetImageBase, sizeIATAdv, sizeIATAdv );
			}
			else
			{
				Logs( "%s IAT Search Adv: IAT not found at OEP " PRINTF_DWORD_PTR_FULL_S "!\n", __FUNCTION__, searchAddress );
			}
		}


		if ( iatSearch.searchImportAddressTableInProcess( searchAddress, &uAddressIAT, &uSizeIAT, false ) )
		{
			Logs( "%s IAT Search Nor: IAT VA " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " Size 0x%04X (%d)\n", __FUNCTION__,
				uAddressIAT, uAddressIAT - ProcessAccessHelp::uTargetImageBase, uSizeIAT, uSizeIAT );
		}
		else
		{
			Logs( "%s IAT Search Nor: IAT not found at OEP " PRINTF_DWORD_PTR_FULL_S "!\n", __FUNCTION__, searchAddress );
		}

		if ( uAddressIAT != 0 && addressIATAdv == 0 )
		{
			setDialogIATAddressAndSize( uAddressIAT, uSizeIAT );
		}
		else if ( uAddressIAT == 0 && addressIATAdv != 0 )
		{
			setDialogIATAddressAndSize( addressIATAdv, sizeIATAdv );
		}
		else if ( uAddressIAT != 0 && addressIATAdv != 0 )
		{
			if ( addressIATAdv != uAddressIAT || uSizeIAT != sizeIATAdv )
			{
				int msgboxID = MessageBox( 0, L"Result of advanced and normal search is different. Do you want to use the IAT Search Advanced result?", L"Information", MB_YESNO | MB_ICONINFORMATION );
				if ( msgboxID == IDYES )
				{
					setDialogIATAddressAndSize( addressIATAdv, sizeIATAdv );
				}
				else
				{
					setDialogIATAddressAndSize( uAddressIAT, uSizeIAT );
				}
			}
			else
			{
				setDialogIATAddressAndSize( uAddressIAT, uSizeIAT );
			}
		}

	}

}

void ScyllaContext::getImportsActionHandler( )
{
	if ( !m_processPtr.PID )
		return;

	if ( !m_addressIAT || !m_sizeIAT )
		return;

	m_apiReader.readAndParseIAT( m_addressIAT, m_sizeIAT, m_importsHandling.vModuleList );

	m_importsHandling.scanAndFixModuleList( );

	m_importsHandling.displayAllImports( );


	if ( Config::SCAN_DIRECT_IMPORTS )
	{
		m_iatReferenceScan.ScanForDirectImports = true;
		m_iatReferenceScan.ScanForNormalImports = false;
		m_iatReferenceScan.apiReader = &m_apiReader;
		m_iatReferenceScan.startScan( ProcessAccessHelp::uTargetImageBase, static_cast<std::uint32_t>( ProcessAccessHelp::uTargetSizeOfImage ), m_addressIAT, m_sizeIAT );

		Logs( "%s DIRECT IMPORTS - Found %d possible direct imports with %d unique APIs!\n", __FUNCTION__, m_iatReferenceScan.numberOfFoundDirectImports( ), m_iatReferenceScan.numberOfFoundUniqueDirectImports( ) );

		if ( m_iatReferenceScan.numberOfFoundDirectImports( ) > 0 )
		{
			if ( m_iatReferenceScan.numberOfDirectImportApisNotInIat( ) > 0 )
			{
				Logs( "%s DIRECT IMPORTS - Found %d additional api addresses!\n", __FUNCTION__, m_iatReferenceScan.numberOfDirectImportApisNotInIat( ) );

				std::uint32_t sizeIatNew = m_iatReferenceScan.addAdditionalApisToList( );

				Logs( "%s DIRECT IMPORTS - Old IAT size 0x%08X new IAT size 0x%08X!\n", __FUNCTION__, m_sizeIAT, sizeIatNew );

				m_sizeIAT = sizeIatNew;

				m_importsHandling.scanAndFixModuleList( );
				m_importsHandling.displayAllImports( );
			}

			m_iatReferenceScan.printDirectImportLog( );

			if ( Config::FIX_DIRECT_IMPORTS_NORMAL && ( Config::FIX_DIRECT_IMPORTS_UNIVERSAL == false ) )
			{
				int msgboxID = MessageBox( 0,
					L"Direct Imports found. I can patch only direct imports by JMP/CALL (use universal method if you don't like this) but where is the junk byte?\r\n\r\nYES = After Instruction\r\nNO = Before the Instruction\r\nCancel = Do nothing", L"Information",
					MB_YESNOCANCEL | MB_ICONINFORMATION );

				if ( msgboxID != IDCANCEL )
				{
					bool isAfter;
					if ( msgboxID == IDYES )
					{
						isAfter = true;
					}
					else
					{
						isAfter = false;
					}

					m_iatReferenceScan.patchDirectImportsMemory( isAfter );

					Logs( "%s DIRECT IMPORTS - Patched! Please dump target.\n", __FUNCTION__ );
				}

			}
		}

	}


	if ( isIATOutsidePeImage( m_addressIAT ) )
	{
		Logs( "%s WARNING! IAT is not inside the PE image, requires rebasing!\n", __FUNCTION__ );
	}

}

void ScyllaContext::setDefaultFolder( const std::wstring& strNewFolder ) {

	if ( m_strDumpFullFilePath.empty( ) )
		return;

	auto nPos = m_strDumpFullFilePath.find_last_of( L'\\' );

	if ( nPos == std::wstring::npos )
		return;

	auto pFileName = m_strDumpFullFilePath.substr( nPos + 1 );
	auto filenameScy = m_strDumpFullFilePathScy.substr( nPos + 1 );

	m_strDumpFullFilePath = strNewFolder + L"\\" + pFileName;
	m_strDumpFullFilePathScy = strNewFolder + L"\\" + filenameScy;
}


ImportsHandling* ScyllaContext::getImportsHandling( )
{
	return &m_importsHandling;
}

ApiReader* ScyllaContext::getApiReader( ) {
	return &m_apiReader;
}

Process* ScyllaContext::getCurrentProcess( ) {
	return &m_processPtr;
}