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
	DWORD dwAttrib = GetFileAttributes( strFilename.c_str( ) );

	return ( dwAttrib != INVALID_FILE_ATTRIBUTES && !( dwAttrib & FILE_ATTRIBUTE_DIRECTORY ) );
}

static 
std::wstring getCurrentDirectory( )
{
	WCHAR buffer[ MAX_PATH ] = { 0 };

	GetCurrentDirectory( MAX_PATH, buffer );

	return std::wstring( buffer );
}

ScyllaContext::ScyllaContext( const std::wstring& strProcessName )
{
	std::vector<Process>& vProcessList = processLister.getProcessListSnapshotNative( );

	std::uint32_t uProcessId = 0;

	for ( auto& vProcess : vProcessList )
	{
		if ( std::wstring( vProcess.filename ).find( strProcessName ) != std::wstring::npos )
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
	if ( strDumpFullFilePath.empty( ) && !ProcessAccessHelp::targetImageBase )
		return;

	PeParser* pPeFile = ( Config::USE_PE_HEADER_FROM_DISK && !strDumpFullFilePath.empty( ) ) ?
		new PeParser( strTargetFilePath.c_str( ), false ) :
		new PeParser( ProcessAccessHelp::targetImageBase, false );

	m_entrypoint = pPeFile->getEntryPoint( ) + processPtr.imageBase;

	auto pDirImport = pPeFile->getDirectory( IMAGE_DIRECTORY_ENTRY_IAT );

	if ( pDirImport )
	{
		DWORD_PTR addressIAT = pDirImport->VirtualAddress;
		DWORD sizeIAT = pDirImport->Size;

		if ( addressIAT && sizeIAT )
		{
			m_addressIAT = addressIAT + processPtr.imageBase;
			m_sizeIAT = sizeIAT;
		}
	}

	if ( !ProcessAccessHelp::targetSizeOfImage )
	{
		ProcessAccessHelp::targetSizeOfImage = pPeFile->getCurrentNtHeader( )->OptionalHeader.SizeOfImage;
	}
}

int ScyllaContext::setProcessById( std::uint32_t uProcessId ) {

	if ( !uProcessId )
	{
		Logs( "%s Process ID not found\n", __FUNCTION__ );
		return SCY_ERROR_PIDNOTFOUND;
	}

	std::vector<Process>& vProcessList = processLister.getProcessListSnapshotNative( );

	for ( auto & vProcess : vProcessList )
	{
		if ( vProcess.PID == uProcessId )
		{
			processPtr = vProcess;
			break;
		}
	}

	vProcessList.clear( );

	if ( !processPtr.PID )
	{
		Logs( "%s Process ID not found 2\n", __FUNCTION__ );
		return SCY_ERROR_PIDNOTFOUND;
	}

	ProcessAccessHelp::closeProcessHandle( );

	apiReader.clearAll( );

	if ( !ProcessAccessHelp::openProcessHandle( processPtr.PID ) )
	{
		Logs( "%s failed to open process\n", __FUNCTION__ );
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::targetImageBase = processPtr.imageBase;

	ProcessAccessHelp::targetSizeOfImage = processPtr.imageSize;

	strTargetFilePath = processPtr.fullPath;

	getPePreInfo( );

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList );

	apiReader.readApisFromModuleList( );

	Logs( "%s Loading modules done.\n", __FUNCTION__ );

	Logs( "%s Imagebase: " PRINTF_DWORD_PTR_FULL_S " Size: %08X\n", __FUNCTION__, processPtr.imageBase, processPtr.imageSize );

	getCurrentDefaultDumpFilename( );

	m_bIsModule = false;

	return SCY_ERROR_SUCCESS;
}

bool ScyllaContext::setTargetModule( const std::wstring& strModuleName ) {

	if ( !ProcessAccessHelp::hProcess )
	{
		return false;
	}

	ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList );

	if ( ProcessAccessHelp::moduleList.empty( ) )
	{
		Logs( "%s failed to list modules\n", __FUNCTION__ );
		return false;
	}

	for ( auto& moduleInfo : ProcessAccessHelp::moduleList )
	{
		if ( std::wstring( moduleInfo.fullPath ).find( strModuleName ) != std::wstring::npos )
		{
			return setTargetModule( moduleInfo.modBaseAddr, moduleInfo.modBaseSize, moduleInfo.fullPath );
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

	//ProcessAccessHelp::selectedModule = nullptr;

	if ( !ProcessAccessHelp::hProcess )
		return false;

	Logs( "%s setTargetModule %ls\n", __FUNCTION__, strModulePath.c_str( ) );

	//processPtr.imageSize = (DWORD)ProcessAccessHelp::targetSizeOfImage;

	if ( ProcessAccessHelp::moduleList.empty( ) )
	{
		Logs( "%s failed to list modules\n", __FUNCTION__ );
		return false;
	}


	//std::unique_ptr<std::uint8_t[ ]> pModuleHeaders( new std::uint8_t[ 0x1000 ] );

	//if ( !ProcessAccessHelp::readMemoryFromProcess( uBaseModule, 0x1000, pModuleHeaders.get( ) ) )
	//	return false;

	//IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>( pModuleHeaders.get( ) );

	//if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
	//	return false;

	//IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>( pModuleHeaders.get( ) + pDosHeader->e_lfanew );

	//if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE )
	//	return false;

	//if ( !uModuleSize )
	//	uModuleSize = pNtHeaders->OptionalHeader.SizeOfImage;

	//m_entrypoint = uBaseModule + pNtHeaders->OptionalHeader.AddressOfEntryPoint;

	if ( processPtr.imageBase != uBaseModule )
	{
		ProcessAccessHelp::targetImageBase = uBaseModule;

		ProcessAccessHelp::targetSizeOfImage = uModuleSize ;

		strTargetFilePath = strModulePath;

		//if ( !strModulePath.empty( ) )
		//{
		//	std::memcpy(
		//		ProcessAccessHelp::selectedModule->fullPath,
		//		strModulePath.c_str( ),
		//		min( strModulePath.size( ) * 2, sizeof( ProcessAccessHelp::selectedModule->fullPath ) ) );
		//}
	}

	//strTargetFilePath = ProcessAccessHelp::selectedModule->fullPath;

	getPePreInfo( );

	getCurrentDefaultDumpFilename( );

	m_bIsModule = true;

	return true;
}

bool ScyllaContext::isIATOutsidePeImage( DWORD_PTR addressIAT ) const
{
	DWORD_PTR minAdd = ProcessAccessHelp::targetImageBase;
	DWORD_PTR maxAdd = minAdd + ProcessAccessHelp::targetSizeOfImage;
	return !( addressIAT > minAdd && addressIAT < maxAdd );
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
			isProcessSuspended = true;
			Logs( "%s Suspending process successful, please resume manually.\n", __FUNCTION__ );
		}
	}
}

bool ScyllaContext::getCurrentDefaultDumpFilename( )
{
	if ( !processPtr.PID )
		return false;

	if ( !isFileExists( strTargetFilePath ) )
	{
		auto currrentDir = getCurrentDirectory( );

		strDumpFullFilePath = currrentDir + ( ( m_bIsModule ) ? L"\\dump.dll" : L"\\dump.exe" );
		strDumpFullFilePathScy = currrentDir + ( ( m_bIsModule ) ? L"\\dump_SCY.dll" : L"\\dump_SCY.exe" );

		return true;
	}

	auto lastSlashPos = strTargetFilePath.find_last_of( L'\\' );

	if ( lastSlashPos != std::wstring::npos ) {

		std::wstring filename = strTargetFilePath.substr( lastSlashPos + 1 );

		auto lastDotPos = filename.find_last_of( L'.' );

		if ( lastDotPos != std::wstring::npos ) {

			filename = strTargetFilePath.substr( 0, lastSlashPos +1 ) + filename.substr( 0, lastDotPos );

			strDumpFullFilePath = filename + ( ( m_bIsModule ) ? L"_dump.dll" : L"_dump.exe" );
			strDumpFullFilePathScy = filename + ( ( m_bIsModule ) ? L"_dump_SCY.dll" : L"_dump_SCY.exe" );

			return true;
		}
	}

	return false;
}

bool ScyllaContext::getCurrentModulePath( std::wstring& outModulePath ) const {

	if ( !processPtr.PID )
		return false;

	outModulePath = strTargetFilePath;

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
	if ( !processPtr.PID )
		return;

	checkSuspendProcess( );

	PeParser* pPeFile = ( Config::USE_PE_HEADER_FROM_DISK ) ?
		new PeParser( strTargetFilePath.c_str( ), true ) :
		new PeParser( ProcessAccessHelp::targetImageBase, true );

	if ( pPeFile->isValidPeFile( ) )
	{
		if ( pPeFile->dumpProcess( ProcessAccessHelp::targetImageBase, m_entrypoint, strDumpFullFilePath.c_str( ) ) )
		{
			Logs( "%s Dump success %ls\n", __FUNCTION__, strDumpFullFilePath.c_str( ) );
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
	DWORD newSize = 0;
	//WCHAR selectedFilePath[ MAX_PATH ];

	//getCurrentModulePath( stringBuffer, _countof( stringBuffer ) );
	//if ( showFileDialog( selectedFilePath, false, NULL, filterExeDll, NULL, stringBuffer ) )
	{
		if ( Config::CREATE_BACKUP )
		{
			if ( !ProcessAccessHelp::createBackupFile( strDumpFullFilePath.c_str( ) ) )
			{
				Logs( "%s Creating backup file failed %ls\n", __FUNCTION__, strDumpFullFilePath.c_str( ) );
			}
		}

		DWORD fileSize = ProcessAccessHelp::getFileSize( strDumpFullFilePath.c_str( ) );

		PeParser peFile( strDumpFullFilePath.c_str( ), true );

		if ( !peFile.isValidPeFile( ) )
		{
			Logs( "%s This is not a valid PE file %ls\n", __FUNCTION__, strDumpFullFilePath.c_str( ) );

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

			if ( peFile.savePeFileToDisk( strDumpFullFilePath.c_str( ) ) )
			{
				newSize = ProcessAccessHelp::getFileSize( strDumpFullFilePath.c_str( ) );

				if ( Config::UPDATE_HEADER_CHECKSUM )
				{
					Logs( "%s Generating PE header checksum\n", __FUNCTION__ );

					if ( !PeParser::updatePeHeaderChecksum( strDumpFullFilePath.c_str( ), newSize ) )
					{
						Logs( "%s Generating PE header checksum FAILED!\n", __FUNCTION__ );
					}
				}

				Logs( "%s Rebuild success %ls\n", __FUNCTION__, strDumpFullFilePath.c_str( ) );
				Logs( "%s -> Old file size 0x%08X new file size 0x%08X (%d %%)\n", __FUNCTION__, fileSize, newSize, ( ( newSize * 100 ) / fileSize ) );
			}
			else
			{
				Logs( "%s Rebuild failed, cannot save file %ls\n", __FUNCTION__, strDumpFullFilePath.c_str( ) );
				MessageBox( 0, L"Rebuild failed. Cannot save file.", L"Failure", MB_ICONERROR );
			}
		}
		else
		{
			Logs( "%s Rebuild failed, cannot read file %ls\n", __FUNCTION__, strDumpFullFilePath.c_str( ) );
			MessageBox( 0, L"Rebuild failed. Cannot read file.", L"Failure", MB_ICONERROR );
		}

	}
}

void ScyllaContext::dumpFixActionHandler( )
{
	if ( !processPtr.PID )
		return;

	ImportRebuilder importRebuild( strDumpFullFilePath.c_str( ) );

	if ( Config::IAT_FIX_AND_OEP_FIX )
	{
		importRebuild.setEntryPointRva( (DWORD)( m_entrypoint - ProcessAccessHelp::targetImageBase ) );
	}

	if ( Config::OriginalFirstThunk_SUPPORT )
	{
		importRebuild.enableOFTSupport( );
	}

	if ( Config::SCAN_DIRECT_IMPORTS && Config::FIX_DIRECT_IMPORTS_UNIVERSAL )
	{
		if ( iatReferenceScan.numberOfFoundDirectImports( ) > 0 )
		{
			importRebuild.iatReferenceScan = &iatReferenceScan;
			importRebuild.BuildDirectImportsJumpTable = true;
		}
	}

	if ( Config::CREATE_NEW_IAT_IN_SECTION )
	{
		importRebuild.iatReferenceScan = &iatReferenceScan;

		DWORD_PTR addressIAT = m_addressIAT;
		DWORD sizeIAT = m_sizeIAT;

		importRebuild.enableNewIatInSection( addressIAT, sizeIAT );
	}


	if ( importRebuild.rebuildImportTable( this->strDumpFullFilePathScy.c_str( ), importsHandling.moduleList ) )
	{
		Logs( "%s Import Rebuild success %ls\n", __FUNCTION__, this->strDumpFullFilePathScy.c_str( ) );
	}
	else
	{
		Logs( "%s Import Rebuild failed %ls\n", __FUNCTION__, strDumpFullFilePath.c_str( ) );
		MessageBox( 0, L"Import Rebuild failed", L"Failure", MB_ICONERROR );
	}

}

void ScyllaContext::setDialogIATAddressAndSize( DWORD_PTR addressIAT, DWORD sizeIAT )
{
	m_addressIAT = addressIAT;
	m_sizeIAT = sizeIAT;

	WCHAR stringBuffer[ 256 ] = { 0 };

	swprintf_s( stringBuffer, L"IAT found:\r\n\r\nStart: " PRINTF_DWORD_PTR_FULL L"\r\nSize: 0x%04X (%d) ", addressIAT, sizeIAT, sizeIAT );
	MessageBox( 0, stringBuffer, L"IAT found", MB_ICONINFORMATION );
}

void ScyllaContext::iatAutosearchActionHandler( )
{
	DWORD_PTR searchAddress = m_entrypoint;
	DWORD_PTR addressIAT = 0, addressIATAdv = 0;
	DWORD sizeIAT = 0, sizeIATAdv = 0;
	IATSearch iatSearch{ };

	if ( !processPtr.PID )
		return;

	if ( searchAddress )
	{

		if ( Config::USE_ADVANCED_IAT_SEARCH )
		{
			if ( iatSearch.searchImportAddressTableInProcess( searchAddress, &addressIATAdv, &sizeIATAdv, true ) )
			{
				Logs( "%s IAT Search Adv: IAT VA " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " Size 0x%04X (%d)\n", __FUNCTION__,
					addressIATAdv, addressIATAdv - ProcessAccessHelp::targetImageBase, sizeIATAdv, sizeIATAdv );
			}
			else
			{
				Logs( "%s IAT Search Adv: IAT not found at OEP " PRINTF_DWORD_PTR_FULL_S "!\n", __FUNCTION__, searchAddress );
			}
		}


		if ( iatSearch.searchImportAddressTableInProcess( searchAddress, &addressIAT, &sizeIAT, false ) )
		{
			Logs( "%s IAT Search Nor: IAT VA " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " Size 0x%04X (%d)\n", __FUNCTION__,
				addressIAT, addressIAT - ProcessAccessHelp::targetImageBase, sizeIAT, sizeIAT );
		}
		else
		{
			Logs( "%s IAT Search Nor: IAT not found at OEP " PRINTF_DWORD_PTR_FULL_S "!\n", __FUNCTION__, searchAddress );
		}

		if ( addressIAT != 0 && addressIATAdv == 0 )
		{
			setDialogIATAddressAndSize( addressIAT, sizeIAT );
		}
		else if ( addressIAT == 0 && addressIATAdv != 0 )
		{
			setDialogIATAddressAndSize( addressIATAdv, sizeIATAdv );
		}
		else if ( addressIAT != 0 && addressIATAdv != 0 )
		{
			if ( addressIATAdv != addressIAT || sizeIAT != sizeIATAdv )
			{
				int msgboxID = MessageBox( 0, L"Result of advanced and normal search is different. Do you want to use the IAT Search Advanced result?", L"Information", MB_YESNO | MB_ICONINFORMATION );
				if ( msgboxID == IDYES )
				{
					setDialogIATAddressAndSize( addressIATAdv, sizeIATAdv );
				}
				else
				{
					setDialogIATAddressAndSize( addressIAT, sizeIAT );
				}
			}
			else
			{
				setDialogIATAddressAndSize( addressIAT, sizeIAT );
			}
		}

	}

}

void ScyllaContext::getImportsActionHandler( )
{
	if ( !processPtr.PID )
		return;

	if ( !m_addressIAT || !m_sizeIAT )
		return;

	apiReader.readAndParseIAT( m_addressIAT, m_sizeIAT, importsHandling.moduleList );

	importsHandling.scanAndFixModuleList( );

	importsHandling.displayAllImports( );


	if ( Config::SCAN_DIRECT_IMPORTS )
	{
		iatReferenceScan.ScanForDirectImports = true;
		iatReferenceScan.ScanForNormalImports = false;
		iatReferenceScan.apiReader = &apiReader;
		iatReferenceScan.startScan( ProcessAccessHelp::targetImageBase, (DWORD)ProcessAccessHelp::targetSizeOfImage, m_addressIAT, m_sizeIAT );

		Logs( "%s DIRECT IMPORTS - Found %d possible direct imports with %d unique APIs!\n", __FUNCTION__, iatReferenceScan.numberOfFoundDirectImports( ), iatReferenceScan.numberOfFoundUniqueDirectImports( ) );

		if ( iatReferenceScan.numberOfFoundDirectImports( ) > 0 )
		{
			if ( iatReferenceScan.numberOfDirectImportApisNotInIat( ) > 0 )
			{
				Logs( "%s DIRECT IMPORTS - Found %d additional api addresses!\n", __FUNCTION__, iatReferenceScan.numberOfDirectImportApisNotInIat( ) );

				DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList( );

				Logs( "%s DIRECT IMPORTS - Old IAT size 0x%08X new IAT size 0x%08X!\n", __FUNCTION__, m_sizeIAT, sizeIatNew );

				m_sizeIAT = sizeIatNew;

				importsHandling.scanAndFixModuleList( );
				importsHandling.displayAllImports( );
			}

			iatReferenceScan.printDirectImportLog( );

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

					iatReferenceScan.patchDirectImportsMemory( isAfter );

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

	if ( strDumpFullFilePath.empty( ) )
		return;

	auto nPos = strDumpFullFilePath.find_last_of( L'\\' );

	if ( nPos == std::wstring::npos )
		return;

	auto filename = strDumpFullFilePath.substr( nPos + 1 );
	auto filenameScy = strDumpFullFilePathScy.substr( nPos + 1 );

	strDumpFullFilePath = strNewFolder + L"\\" + filename;
	strDumpFullFilePathScy = strNewFolder + L"\\" + filenameScy;
}


ImportsHandling* ScyllaContext::getImportsHandling( ) 
{ 
	return &importsHandling; 
}