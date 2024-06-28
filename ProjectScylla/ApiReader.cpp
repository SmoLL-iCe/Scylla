
#include "ApiReader.h"
#include "ScyllaConfig.hpp"
#include "Architecture.h"
#include "SystemInformation.h"
#include "StringConversion.h"
#include "PeParser.h"
#include "Tools/Logs.h"
#include <span>
#include "WinApi/ApiTools.h"

#undef min
#undef max

stdext::hash_multimap<std::uintptr_t, ApiInfo*> ApiReader::mpApiList; //api look up table
std::map<std::uintptr_t, ImportModuleThunk>* ApiReader::mpModuleThunkList; //store found apis

std::uintptr_t ApiReader::uMinApiAddress = static_cast<std::uintptr_t>( - 1 );
std::uintptr_t ApiReader::uMaxApiAddress = 0;

void ApiReader::readApisFromModuleList( )
{
	readExportTableAlwaysFromDisk = Config::APIS_ALWAYS_FROM_DISK;

	for ( auto& pModule : vModuleList )
	{
		setModulePriority( &pModule );

		if ( pModule.uModBase + pModule.uModBaseSize > uMaxValidAddress )
		{
			uMaxValidAddress = pModule.uModBase + pModule.uModBaseSize;
		}

		LOGS_DEBUG( "Module parsing: %ls", pModule.pModulePath );

		if ( !pModule.isAlreadyParsed )
		{
			parseModule( &pModule );
		}
	}

	LOGS( "Address Min " PRINTF_DWORD_PTR_FULL_S " Max " PRINTF_DWORD_PTR_FULL_S "\nimagebase " PRINTF_DWORD_PTR_FULL_S " uMaxValidAddress " PRINTF_DWORD_PTR_FULL_S,
		uMinApiAddress, uMaxApiAddress, uTargetImageBase, uMaxValidAddress );
}

void ApiReader::parseModule( ModuleInfo* pModule )
{
	pModule->parsing = true;


	if ( isWinSxSModule( pModule ) || ( readExportTableAlwaysFromDisk && !isModuleLoadedInOwnProcess( pModule ) ) )
	{
		parseModuleWithMapping( pModule );
	}
	else 
	if ( 
#ifdef WIN64
		ProcessAccessHelp::is64BitProcess &&
#endif	
		isModuleLoadedInOwnProcess( pModule ) )
	{
		parseModuleWithOwnProcess( pModule );
	}
	else 
	{
		parseModuleWithProcess( pModule );
	}

	pModule->isAlreadyParsed = true;
}

void ApiReader::parseModuleWithMapping( ModuleInfo* pModuleInfo )
{
	std::unique_ptr<PeParser> peParser = std::make_unique<PeParser>( );

	if ( !peParser->initializeWithMapping( pModuleInfo->pModulePath ) )
	{
		LOGS( "parseModuleWithMapping :: Error initializing with mapping %ls", pModuleInfo->pModulePath );
		return;
	}

	if ( !peParser->isValidExportTable( ) )
		return;

	parseExportTable( pModuleInfo, peParser );
}

void ApiReader::parseModuleWithProcess( ModuleInfo* pModule )
{
	std::unique_ptr<PeParser> peParser = std::make_unique<PeParser>( );

	if ( !peParser->initializeFromRemoteModule( pModule->uModBase, pModule->uModBaseSize ) )
	{
		LOGS( "parseModuleWithProcess :: Error initializing from remote module %ls", pModule->pModulePath );
		return;
	}

	if ( !peParser->isValidExportTable( ) )
		return;

	parseExportTable( pModule, peParser );
}

void ApiReader::parseModuleWithOwnProcess( ModuleInfo* pModule ) {

	HMODULE hModule = GetModuleHandle( pModule->getFilename( ) );

	if ( hModule ) {

		std::unique_ptr<PeParser> peParser = std::make_unique<PeParser>( );

		peParser->initializeFromMapped( hModule );

		if ( !peParser->isValidExportTable( ) ) {
			return;
		}

		parseExportTable( pModule, peParser );
		
	}
	else {
		LOGS( "parseModuleWithOwnProcess :: hModule is nullptr" );
	}
}

void ApiReader::parseExportTable( ModuleInfo* pModule, std::unique_ptr<PeParser>& peParser )
{
	if ( !peParser->isValidExportTable( ) ) 
	{
		return;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDir = peParser->getExportData( );

	if ( 
		pExportDir->AddressOfFunctions > peParser->getDataPESize( ) 
		|| pExportDir->AddressOfNames > peParser->getDataPESize( )
		|| pExportDir->AddressOfNameOrdinals > peParser->getDataPESize( )
		)
	{
		LOGS( "parseExportTable :: AddressOfFunctions/AddressOfNames/AddressOfNameOrdinals is invalid %ls", pModule->pModulePath );
		return;
	}

	std::uintptr_t uDeltaAddress = reinterpret_cast<std::uintptr_t>( peParser->getDataPE( ) );

	auto pAddressOfFuncs = reinterpret_cast<std::uint32_t*>( static_cast<std::uintptr_t>( pExportDir->AddressOfFunctions ) + uDeltaAddress );
	auto pAddressOfNames = reinterpret_cast<std::uint32_t*>( static_cast<std::uintptr_t>( pExportDir->AddressOfNames ) + uDeltaAddress );
	auto pAddressOfNameOrdinals = reinterpret_cast<std::uint16_t*>( static_cast<std::uintptr_t>( pExportDir->AddressOfNameOrdinals ) + uDeltaAddress );



	LOGS( "parseExportTable :: pModule %ls NumberOfNames %X", pModule->pModulePath, pExportDir->NumberOfNames );

	for ( std::uint16_t i = 0; i < pExportDir->NumberOfNames; i++ )
	{
		auto uAddrNameOffset = pAddressOfNames[ i ];

		auto pFuncName = reinterpret_cast<char*>( uAddrNameOffset + uDeltaAddress );


		std::uint16_t uOrdinal = static_cast<std::uint16_t>( pAddressOfNameOrdinals[ i ] + pExportDir->Base );
		std::uintptr_t RVA = pAddressOfFuncs[ pAddressOfNameOrdinals[ i ] ];
		std::uintptr_t VA = RVA + pModule->uModBase;

		LOGS( "parseExportTable :: api %s uOrdinal %d imagebase " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " VA " PRINTF_DWORD_PTR_FULL_S, pFuncName, uOrdinal, pModule->uModBase, RVA, VA );

		if ( !isApiBlacklisted( pFuncName ) )
		{
			if ( !peParser->isApiForwarded( RVA ) )
			{
				addApi( pFuncName, i, uOrdinal, VA, RVA, false, pModule );
			}
			else
			{
				handleForwardedApi( RVA + uDeltaAddress, pFuncName, RVA, uOrdinal, pModule );
			}
		}
	}

	// Exports without name
	if ( pExportDir->NumberOfNames != pExportDir->NumberOfFunctions )
	{
		for ( std::uint16_t i = 0; i < pExportDir->NumberOfFunctions; i++ )
		{
			bool bWithoutName = true;
			for ( std::uint16_t j = 0; j < pExportDir->NumberOfNames; j++ )
			{
				if ( pAddressOfNameOrdinals[ j ] == i )
				{
					bWithoutName = false;
					break;
				}
			}
			if ( bWithoutName && pAddressOfFuncs[ i ] != 0 )
			{
				std::uint16_t uOrdinal = static_cast<std::uint16_t>( i + pExportDir->Base );
				std::uintptr_t RVA = pAddressOfFuncs[ i ];
				std::uintptr_t VA = RVA + pModule->uModBase;

				if ( !peParser->isApiForwarded( RVA ) )
				{
					addApiWithoutName( uOrdinal, VA, RVA, false, pModule );
				}
				else
				{
					handleForwardedApi( RVA + uDeltaAddress, nullptr, RVA, uOrdinal, pModule );
				}
			}
		}
	}
}


bool ApiReader::isApiForwarded( std::uintptr_t RVA, PIMAGE_NT_HEADERS pNtHeader )
{
	auto DirExport = pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	return ( RVA > DirExport.VirtualAddress )
		&& ( RVA < ( DirExport.VirtualAddress + DirExport.Size ) );
}

void ApiReader::handleForwardedApi( std::uintptr_t uVaStringPointer, const char* pFuncNameParent, std::uintptr_t uRvaParent, std::uint16_t uOrdinalParent, ModuleInfo* pModuleParent ) {

	auto pForwardedString = reinterpret_cast<char*>( uVaStringPointer );

	std::uint16_t uOrdinal = 0;
	std::uintptr_t uVaApi = 0;
	std::uintptr_t uRvaApi = 0;

	auto nPos = std::strchr( pForwardedString, '.' );

	if ( !nPos )
		return;

	std::string strDllName = "";

	strDllName.assign( pForwardedString, nPos );

	std::string strSearchFunctionName = nPos + 1;

	if ( auto pHashPos = std::strchr( strSearchFunctionName.c_str( ), '#' ) ) {
		strSearchFunctionName = pHashPos + 1;
		uOrdinal = static_cast<std::uint16_t>( std::atoi( strSearchFunctionName.c_str( ) ) );
	}

	if ( !_strnicmp( strDllName.c_str( ), "API-", 4 ) || !_strnicmp( strDllName.c_str( ), "EXT-", 4 ) ) {
		HMODULE hModTemp = GetModuleHandleA( strDllName.c_str( ) );
		if ( !hModTemp ) {

			hModTemp = LoadLibraryExA( strDllName.c_str( ), nullptr, DONT_RESOLVE_DLL_REFERENCES );
		}

		if ( hModTemp ) {
			FARPROC pAddy = uOrdinal ? GetProcAddress( hModTemp, reinterpret_cast<LPCSTR>( uOrdinal ) ) : GetProcAddress( hModTemp, strSearchFunctionName.c_str( ) );

			if ( pAddy ) {
				addApi( pFuncNameParent, 0, uOrdinalParent, reinterpret_cast<std::uintptr_t>( pAddy ), reinterpret_cast<std::uintptr_t>( pAddy ) - reinterpret_cast<std::uintptr_t>( hModTemp ), true, pModuleParent );
			}
			return;
		}
	}

	strDllName += ".dll";

	std::wstring strDllNameW( strDllName.begin( ), strDllName.end( ) );

	ModuleInfo* pModule = ( !_wcsicmp( strDllNameW.c_str( ), pModuleParent->getFilename( ) ) ) ? pModuleParent : findModuleByName( strDllNameW.c_str( ) );

	if ( pModule ) {

		if ( uOrdinal ) {

			findApiByModuleAndOrdinal( pModule, uOrdinal, &uVaApi, &uRvaApi );

		}
		else {

			findApiByModuleAndName( pModule, strSearchFunctionName.c_str( ), &uVaApi, &uRvaApi );
		}

		if ( uRvaApi == 0 ) {
			LOGS( "handleForwardedApi :: Api not found, this is really BAD! %s", pForwardedString );
		}
		else {
			addApi( pFuncNameParent, 0, uOrdinalParent, uVaApi, uRvaApi, true, pModuleParent );
		}
	}
}

ModuleInfo* ApiReader::findModuleByName( const wchar_t* pName )
{
	for ( std::uint32_t i = 0; i < vModuleList.size( ); i++ ) {
		if ( !_wcsicmp( vModuleList[ i ].getFilename( ), pName ) )
		{
			return &vModuleList[ i ];
		}
	}

	return 0;
}

void ApiReader::addApiWithoutName( std::uint16_t uOrdinal, std::uintptr_t VA, std::uintptr_t RVA, bool isForwarded, ModuleInfo* pModuleInfo )
{
	addApi( 0, 0, uOrdinal, VA, RVA, isForwarded, pModuleInfo );
}

void ApiReader::addApi( const char* pFuncName, std::uint16_t uHint, std::uint16_t uOrdinal, std::uintptr_t VA, std::uintptr_t RVA, bool isForwarded, ModuleInfo* pModuleInfo )
{
	ApiInfo* pApiInfo = new ApiInfo( );

	if ( ( pFuncName != 0 ) && ( strlen( pFuncName ) < _countof( pApiInfo->name ) ) )
	{
		strcpy_s( pApiInfo->name, pFuncName );
	}
	else
	{
		pApiInfo->name[ 0 ] = 0x00;
	}

	pApiInfo->uOrdinal = uOrdinal;
	pApiInfo->isForwarded = isForwarded;
	pApiInfo->pModule = pModuleInfo;
	pApiInfo->uRVA = RVA;
	pApiInfo->uVA = VA;
	pApiInfo->uHint = uHint;

	setMinMaxApiAddress( VA );

	pModuleInfo->vApiList.push_back( pApiInfo );

	mpApiList.insert( API_Pair( VA, pApiInfo ) );
}

void ApiReader::findApiByModuleAndOrdinal( ModuleInfo* pModule, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi )
{
	findApiByModule( pModule, 0, uOrdinal, pVaApi, pRvaApi );
}

void ApiReader::findApiByModuleAndName( ModuleInfo* pModule, const char* pSearchFunctionName, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi )
{
	findApiByModule( pModule, pSearchFunctionName, 0, pVaApi, pRvaApi );
}

void ApiReader::findApiByModule( ModuleInfo* pModule, const char* pSearchFunctionName, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi ) {
	if ( isModuleLoadedInOwnProcess( pModule ) ) {
		HMODULE hModule = GetModuleHandle( pModule->getFilename( ) );

		if ( hModule ) {
			if ( pVaApi ) {
				FARPROC procAddress = uOrdinal ? GetProcAddress( hModule, MAKEINTRESOURCEA( uOrdinal ) ) : GetProcAddress( hModule, pSearchFunctionName );
				if ( procAddress ) {
					*pVaApi = reinterpret_cast<std::uintptr_t>( procAddress );
					*pRvaApi = *pVaApi - reinterpret_cast<std::uintptr_t>( hModule );
					*pVaApi = *pRvaApi + pModule->uModBase;
				}
			}
			else {
				LOGS( "findApiByModule :: pVaApi == nullptr, should never happen %s", pSearchFunctionName );
			}
		}
		else {
			LOGS( "findApiByModule :: hModule == nullptr, should never happen %ls", pModule->getFilename( ) );
		}
	}
	else {
		// Search API in external process
		findApiInProcess( pModule, pSearchFunctionName, uOrdinal, pVaApi, pRvaApi );
	}
}

bool ApiReader::isModuleLoadedInOwnProcess( ModuleInfo* pModule ) {
	for ( const auto& Module : vOwnModuleList ) {
		if ( !_wcsicmp( pModule->pModulePath, Module.pModulePath ) ) {
			return true;
		}
	}
	return false;
}

void ApiReader::findApiInProcess( ModuleInfo* pModule, const char* pSearchFunctionName, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi )
{
	std::unique_ptr<PeParser> peParser = std::make_unique<PeParser>( );

	if ( !peParser->initializeFromRemoteModule( pModule->uModBase, pModule->uModBaseSize ) )
	{
		LOGS( "parseModuleWithProcess :: Error initializing from remote module %ls", pModule->pModulePath );
		return;
	}

	if ( !peParser->isValidExportTable( ) )
		return;

	findApiInExportTable( pModule, peParser,
				pSearchFunctionName, uOrdinal, pVaApi, pRvaApi );
}

bool ApiReader::findApiInExportTable( ModuleInfo* pModule, std::unique_ptr<PeParser>& peParser, const char* pSearchFunctionName, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi )
{
	PIMAGE_EXPORT_DIRECTORY pExportDir = peParser->getExportData( );
	
	std::uintptr_t uDeltaAddress = reinterpret_cast<std::uintptr_t>( peParser->getDataPE( ) );


	auto pAddressOfFuncs = reinterpret_cast<std::uint32_t*>( static_cast<std::uintptr_t>( pExportDir->AddressOfFunctions ) + uDeltaAddress );
	auto pAddressOfNames = reinterpret_cast<std::uint32_t*>( static_cast<std::uintptr_t>( pExportDir->AddressOfNames ) + uDeltaAddress );
	auto pAddressOfNameOrdinals = reinterpret_cast<std::uint16_t*>( static_cast<std::uintptr_t>( pExportDir->AddressOfNameOrdinals ) + uDeltaAddress );

	if ( pSearchFunctionName )
	{
		for ( std::uint32_t i = 0; i < pExportDir->NumberOfNames; i++ )
		{
			auto pFuncName = reinterpret_cast<char*>( pAddressOfNames[ i ] + uDeltaAddress );

			if ( !strcmp( pFuncName, pSearchFunctionName ) )
			{
				*pRvaApi = pAddressOfFuncs[ pAddressOfNameOrdinals[ i ] ];
				*pVaApi = pAddressOfFuncs[ pAddressOfNameOrdinals[ i ] ] + pModule->uModBase;
				return true;
			}
		}
	}
	else
	{
		for ( std::uint32_t i = 0; i < pExportDir->NumberOfFunctions; i++ )
		{
			if ( uOrdinal == ( i + pExportDir->Base ) )
			{
				*pRvaApi = pAddressOfFuncs[ i ];
				*pVaApi = pAddressOfFuncs[ i ] + pModule->uModBase;
				return true;
			}
		}
	}

	return false;
}

void ApiReader::setModulePriority( ModuleInfo* pModule ) {
	const wchar_t* pModuleFileName = pModule->getFilename( );

	if ( !_wcsicmp( pModuleFileName, L"kernelbase.dll" ) ) {
		pModule->nPriority = -1;
	}
	else if ( !_wcsicmp( pModuleFileName, L"ntdll.dll" )
		|| !_wcsicmp( pModuleFileName, L"shlwapi.dll" )
		|| !_wcsicmp( pModuleFileName, L"ShimEng.dll" )
		|| !_wcsnicmp( pModuleFileName, L"API-", 4 )
		|| !_wcsnicmp( pModuleFileName, L"EXT-", 4 ) ) {
		pModule->nPriority = 0;
	}
	else if ( !_wcsicmp( pModuleFileName, L"kernel32.dll" ) ) {
		pModule->nPriority = 2;
	}
	else {
		pModule->nPriority = 1;
	}
}

bool ApiReader::isApiAddressValid( std::uintptr_t uVirtualAddress )
{
	return mpApiList.count( uVirtualAddress ) > 0;
}

ApiInfo* ApiReader::getApiByVirtualAddress( std::uintptr_t uVirtualAddress, bool* pIsSuspect ) {

	*pIsSuspect = false;
	auto range = mpApiList.equal_range( uVirtualAddress );

	std::size_t countDuplicates = std::distance( range.first, range.second );

	if ( countDuplicates == 0 ) {
		return nullptr;
	}
	else if ( countDuplicates == 1 ) {
		// API is 100% correct
		return range.first->second;
	}
	else {
		auto& it = range.first;

		// any high nPriority with a name
		auto pApiFound = getScoredApi( it, countDuplicates, true, false, false, true, false, false, false, false );
		if ( pApiFound ) return pApiFound;

		*pIsSuspect = true;

		// high nPriority with a name and ansi/unicode name
		pApiFound = getScoredApi( it, countDuplicates, true, true, false, true, false, false, false, false );
		if ( pApiFound ) return pApiFound;

		// nPriority 2 with no underline in name
		pApiFound = getScoredApi( it, countDuplicates, true, false, true, false, false, false, true, false );
		if ( pApiFound ) return pApiFound;

		// nPriority 1 with a name
		pApiFound = getScoredApi( it, countDuplicates, true, false, false, false, false, true, false, false );
		if ( pApiFound ) return pApiFound;

		// with a name
		pApiFound = getScoredApi( it, countDuplicates, true, false, false, false, false, false, false, false );
		if ( pApiFound ) return pApiFound;

		// any with nPriority, name, ansi/unicode
		pApiFound = getScoredApi( it, countDuplicates, true, true, false, true, false, false, false, true );
		if ( pApiFound ) return pApiFound;

		// any with nPriority
		pApiFound = getScoredApi( it, countDuplicates, false, false, false, true, false, false, false, true );
		if ( pApiFound ) return pApiFound;

		// has prio 0 and name
		pApiFound = getScoredApi( it, countDuplicates, false, false, false, false, true, false, false, true );
		if ( pApiFound ) return pApiFound;
	}

	// is never reached
	LOGS_DEBUG( "getApiByVirtualAddress :: There is an API resolving bug, VA: " PRINTF_DWORD_PTR_FULL_S, uVirtualAddress );

	for ( auto& it = range.first; it != range.second; ++it ) {
		auto pApiFound = it->second;
		LOGS_DEBUG( "-> Possible API: %s ord: %d ", pApiFound->name, pApiFound->uOrdinal );
	}

	return reinterpret_cast<ApiInfo*>( 1 );
}

ApiInfo* ApiReader::getScoredApi( stdext::hash_multimap<std::uintptr_t, ApiInfo*>::iterator it, std::size_t szCountDuplicates,
	bool bHasName, bool bHasUnicodeAnsiName,
	bool bHasNoUnderlineInName, bool bHasPrioDll, bool bHasPrio0Dll, bool bHasPrio1Dll, bool bHasPrio2Dll, bool bFirstWin ) {

	ApiInfo* foundMatchingApi = nullptr;
	int nCountFoundApis = 0;
	int nScoreNeeded = bHasName + bHasUnicodeAnsiName + bHasNoUnderlineInName + bHasPrioDll + bHasPrio0Dll + bHasPrio1Dll + bHasPrio2Dll;

	for ( std::size_t i = 0; i < szCountDuplicates; ++i, ++it ) {
		ApiInfo* pFoundApi = it->second;
		int nScoreValue = 0;

		if ( bHasName && pFoundApi->name[ 0 ] != '\0' ) {
			++nScoreValue;
			if ( bHasUnicodeAnsiName ) {
				std::size_t szApiNameLength = std::strlen( pFoundApi->name );
				if ( pFoundApi->name[ szApiNameLength - 1 ] == 'W' || pFoundApi->name[ szApiNameLength - 1 ] == 'A' ) {
					++nScoreValue;
				}
			}
			if ( bHasNoUnderlineInName && !std::strrchr( pFoundApi->name, '_' ) ) {
				++nScoreValue;
			}
		}

		if ( bHasPrioDll && pFoundApi->pModule->nPriority >= 1 ) ++nScoreValue;
		if ( bHasPrio0Dll && pFoundApi->pModule->nPriority == 0 ) ++nScoreValue;
		if ( bHasPrio1Dll && pFoundApi->pModule->nPriority == 1 ) ++nScoreValue;
		if ( bHasPrio2Dll && pFoundApi->pModule->nPriority == 2 ) ++nScoreValue;

		if ( nScoreValue == nScoreNeeded ) {
			foundMatchingApi = pFoundApi;
			++nCountFoundApis;
			if ( bFirstWin ) return foundMatchingApi;
		}
	}

	return nCountFoundApis == 1 ? foundMatchingApi : nullptr;
}

void ApiReader::setMinMaxApiAddress( std::uintptr_t uVirtualAddress )
{
	if ( uVirtualAddress == 0 || uVirtualAddress == static_cast<std::uintptr_t>( -1 ) )
		return;

	if ( uVirtualAddress < uMinApiAddress )
	{
		LOGS( "uVirtualAddress %p < uMinApiAddress %p", uVirtualAddress, uMinApiAddress );
		uMinApiAddress = uVirtualAddress - 1;
	}
	if ( uVirtualAddress > uMaxApiAddress )
	{
		uMaxApiAddress = uVirtualAddress + 1;
	}
}

void ApiReader::readAndParseIAT( std::uintptr_t uAddressIAT, std::uint32_t uSizeIAT, std::map<std::uintptr_t, ImportModuleThunk>& mpModuleListNew )
{
	mpModuleThunkList = &mpModuleListNew;

	auto pDataIat = std::make_unique<std::uint8_t[ ]>( uSizeIAT );

	if ( readMemoryFromProcess( uAddressIAT, uSizeIAT, pDataIat.get( ) ) )
	{
		parseIAT( uAddressIAT, pDataIat.get( ), uSizeIAT );
	}
	else
	{
		LOGS( "ApiReader::readAndParseIAT :: error reading iat " PRINTF_DWORD_PTR_FULL_S, uAddressIAT );
	}
}

void ApiReader::parseIAT( std::uintptr_t uAddressIAT, std::uint8_t* pIatBuffer, std::size_t szSize )
{
	if ( !uAddressIAT || !pIatBuffer || !szSize )
	{
		return;
	}

	std::size_t szTableSize = szSize / sizeof( std::uintptr_t );

#ifdef WIN64
	
	if ( !ProcessAccessHelp::is64BitProcess && szTableSize )
		szTableSize /= 2;

#endif // WIN64

	ModuleInfo* pModule = nullptr;
	bool isSuspect = false;
	int nCountApiFound = 0, nCountApiNotFound = 0;

	for ( size_t i = 0; i < szTableSize; i++ ) {

#ifdef WIN64
		std::uintptr_t uAddress = 0;

		std::uintptr_t uIatEntryAddress = 0;

		if ( ProcessAccessHelp::is64BitProcess ) { 
			uAddress = reinterpret_cast<std::uintptr_t*>( pIatBuffer )[ i ];
			uIatEntryAddress = uAddressIAT + i * sizeof( std::uintptr_t );
		}
		else { 
			uAddress = reinterpret_cast<std::uint32_t*>( pIatBuffer )[ i ];
			uIatEntryAddress = uAddressIAT + i * sizeof( std::uint32_t );
		}
#else
		std::uintptr_t uAddress = reinterpret_cast<std::uintptr_t*>( pIatBuffer )[ i ];

		std::uintptr_t uIatEntryAddress = uAddressIAT + i * sizeof( std::uintptr_t );
#endif // WIN64

		if ( isInvalidMemoryForIat( uAddress ) )
			continue;

		if ( uAddress > uMinApiAddress && uAddress < uMaxApiAddress )
		{
			auto pApiFound = getApiByVirtualAddress( uAddress, &isSuspect );

			LOGS( "pApiFound %p uAddress %p", pApiFound, uAddress );

			if ( pApiFound == nullptr )
			{
				LOGS_DEBUG( "getApiByVirtualAddress :: No Api found " PRINTF_DWORD_PTR_FULL_S, uAddress );
			}
			else if ( pApiFound == reinterpret_cast<ApiInfo*>( 1 ) )
			{
				LOGS( "pApiFound == reinterpret_cast<ApiInfo*>( 1 ) -> " PRINTF_DWORD_PTR_FULL_S, uAddress );
			}
			else
			{
				nCountApiFound++;
				LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " %ls %d %s", pApiFound->uVA, pApiFound->pModule->getFilename( ), pApiFound->uOrdinal, pApiFound->name );

				if ( pModule != pApiFound->pModule )
				{
					pModule = pApiFound->pModule;
					addFoundApiToModuleList( uIatEntryAddress, pApiFound, true, isSuspect );
				}
				else
				{
					addFoundApiToModuleList( uIatEntryAddress, pApiFound, false, isSuspect );
				}
			}
		}
		else
		{
			nCountApiNotFound++;
			addNotFoundApiToModuleList( uIatEntryAddress, uAddress );
		}
		
	}

	LOGS_DEBUG( "IAT parsing finished, found %d valid APIs, missed %d APIs", nCountApiFound, nCountApiNotFound );
}

void ApiReader::addFoundApiToModuleList( std::uintptr_t uIatAddressVA, ApiInfo* pApiFound, bool isNewModule, bool isSuspect )
{
	if ( isNewModule )
	{
		addModuleToModuleList( pApiFound->pModule->getFilename( ), uIatAddressVA - uTargetImageBase );
	}
	addFunctionToModuleList( pApiFound, uIatAddressVA, uIatAddressVA - uTargetImageBase, pApiFound->uOrdinal, true, isSuspect );
}

bool ApiReader::addModuleToModuleList( const wchar_t* pModuleName, std::uintptr_t uFirstThunk )
{
	ImportModuleThunk ModuleThunk{};

	ModuleThunk.uFirstThunk = uFirstThunk;
	wcscpy_s( ModuleThunk.pModuleName, pModuleName );

	( *mpModuleThunkList ).insert( std::pair<std::uintptr_t, ImportModuleThunk>( uFirstThunk, ModuleThunk ) );

	return true;
}

void ApiReader::addUnknownModuleToModuleList( std::uintptr_t uFirstThunk )
{
	ImportModuleThunk ModuleThunk{};

	ModuleThunk.uFirstThunk = uFirstThunk;
	wcscpy_s( ModuleThunk.pModuleName, L"?" );

	( *mpModuleThunkList ).insert( std::pair<std::uintptr_t, ImportModuleThunk>( uFirstThunk, ModuleThunk ) );
}

bool ApiReader::addFunctionToModuleList( ApiInfo* pApiFound, std::uintptr_t VA, std::uintptr_t RVA, std::uint16_t uOrdinal, bool valid, bool suspect ) {
	if ( !mpModuleThunkList || mpModuleThunkList->empty( ) ) {
		LOGS( "ImportsHandling::addFunction mpModuleThunkList is empty" );
		return false;
	}

	auto pModule = findModuleForRVA( RVA );
	if ( !pModule ) {
		LOGS( "ImportsHandling::addFunction pModule not found RVA " PRINTF_DWORD_PTR_FULL_S, RVA );
		return false;
	}

	ImportThunk pImport {
		.uVA = VA,
		.uRVA = RVA,
		.uOrdinal = uOrdinal,
		.uApiAddressVA = pApiFound->uVA,
		.uHint = static_cast<std::uint16_t>( pApiFound->uHint ),
		.bValid = valid,
		.bSuspect = suspect,
	};

	wcscpy_s( pImport.pModuleName, pApiFound->pModule->getFilename( ) );
	strcpy_s( pImport.name, pApiFound->name );

	pModule->mpThunkList.insert( { pImport.uRVA, pImport } );

	return true;
}

bool ApiReader::addNotFoundApiToModuleList( std::uintptr_t uIatAddressVA, std::uintptr_t uApiAddress ) {
	if ( !mpModuleThunkList || mpModuleThunkList->empty( ) ) {
		addUnknownModuleToModuleList( uIatAddressVA - uTargetImageBase );
	}

	std::uintptr_t RVA = uIatAddressVA - uTargetImageBase;
	auto pModule = findModuleForRVA( RVA, true );

	if ( !pModule ) {
		LOGS( "ImportsHandling::addFunction pModule not found RVA " PRINTF_DWORD_PTR_FULL_S, RVA );
		return false;
	}

	ImportThunk pImport {
		.pModuleName = L"?",
		.name = "?",
		.uVA = uIatAddressVA,
		.uRVA = RVA,
		.uOrdinal = 0,
		.uApiAddressVA = uApiAddress,
		.bValid = false,
		.bSuspect = true
	};

	pModule->mpThunkList.insert( { pImport.uRVA, pImport } );

	return true;
}

ImportModuleThunk* ApiReader::findModuleForRVA( std::uintptr_t RVA, bool addUnknownModuleIfNeeded ) {
	auto it = std::find_if( mpModuleThunkList->begin( ), mpModuleThunkList->end( ),
		[RVA]( const auto& pair ) { return RVA >= pair.second.uFirstThunk; } );

	if ( it == mpModuleThunkList->end( ) || ( RVA < it->second.uFirstThunk && it != mpModuleThunkList->begin( ) ) ) {
		--it; // Adjust iterator to point to the correct pModule
	}

	if ( it == mpModuleThunkList->end( ) || ( addUnknownModuleIfNeeded && it->second.pModuleName[ 0 ] != L'?' ) ) {
		if ( addUnknownModuleIfNeeded ) {
			addUnknownModuleToModuleList( RVA );
			return &mpModuleThunkList->find( RVA )->second;
		}
		return nullptr;
	}

	return &it->second;
}

void ApiReader::clearAll( ) {
	uMinApiAddress = static_cast<std::uintptr_t>( -1 );
	uMaxApiAddress = 0;

	for ( auto& [key, apiInfo] : mpApiList ) {
		delete apiInfo;
	}
	mpApiList.clear( );

	if ( mpModuleThunkList != nullptr ) {
		mpModuleThunkList->clear( );
	}
}

bool ApiReader::isApiBlacklisted( const char* pFuncName ) {
	return SystemInformation::currenOS < WIN_VISTA_32 && !strcmp( pFuncName, "RestoreLastError" );
}

bool ApiReader::isWinSxSModule( ModuleInfo* pModule ) {
	const wchar_t* pModulePath = pModule->pModulePath;
	return wcsstr( pModulePath, L"\\WinSxS\\" ) || wcsstr( pModulePath, L"\\winsxs\\" );
}

bool ApiReader::isInvalidMemoryForIat( std::uintptr_t uAddress ) {
	if ( uAddress == 0 || uAddress == static_cast<std::uintptr_t>( -1 ) )
		return true;

	MEMORY_BASIC_INFORMATION memBasic {};

	if ( ApiTools::VirtualQueryEx( ProcessAccessHelp::hProcess, reinterpret_cast<LPVOID>( uAddress ), &memBasic, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
		return !( memBasic.State == MEM_COMMIT && ProcessAccessHelp::isPageAccessable( memBasic.Protect ) );
	}
	return true;
}
