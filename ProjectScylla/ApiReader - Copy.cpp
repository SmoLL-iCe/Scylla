
#include "ApiReader.h"
#include "ScyllaConfig.hpp"
#include "Architecture.h"
#include "SystemInformation.h"
#include "StringConversion.h"
#include "PeParser.h"
#include "Tools/Logs.h"
#include <string>
#include <algorithm>

std::unordered_map<DWORD_PTR, ApiInfo*> ApiReader::apiList; //api look up table
std::map<DWORD_PTR, ImportModuleThunk>* ApiReader::moduleThunkList; //store found apis

DWORD_PTR ApiReader::minApiAddress = (DWORD_PTR)-1;
DWORD_PTR ApiReader::maxApiAddress = 0;

void ApiReader::readApisFromModuleList( )
{
	readExportTableAlwaysFromDisk = Config::APIS_ALWAYS_FROM_DISK;

	for ( unsigned int i = 0; i < moduleList.size( );i++ )
	{
		setModulePriority( &moduleList[ i ] );

		if ( moduleList[ i ].modBaseAddr + moduleList[ i ].modBaseSize > maxValidAddress )
			maxValidAddress = moduleList[ i ].modBaseAddr + moduleList[ i ].modBaseSize;
		

		LOGS( "Module parsing: %ls", moduleList[ i ].fullPath );

		if ( !moduleList[ i ].isAlreadyParsed )
			parseModule( &moduleList[ i ] );
		
	}

	LOGS_DEBUG( "Address Min " PRINTF_DWORD_PTR_FULL_S " Max " PRINTF_DWORD_PTR_FULL_S "\nimagebase " PRINTF_DWORD_PTR_FULL_S " maxValidAddress " PRINTF_DWORD_PTR_FULL_S, 
		minApiAddress, maxApiAddress, targetImageBase, maxValidAddress );
}

void ApiReader::parseModule( ModuleInfo* module )
{
	module->parsing = true;

	// Simplify the conditional logic
	if ( isWinSxSModule( module ) || readExportTableAlwaysFromDisk || isModuleLoadedInOwnProcess( module ) )
	{
		parseModuleWithMapping( module );
	}
	else
	{
		parseModuleWithProcess( module );
	}

	module->isAlreadyParsed = true;
}

void ApiReader::parseModuleWithMapping( ModuleInfo* moduleInfo )
{
	auto fileMapping = createFileMappingViewRead( moduleInfo->fullPath );

	if ( !fileMapping )
		return;

	auto pDosHeader = static_cast<PIMAGE_DOS_HEADER>( fileMapping );
	auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<DWORD_PTR>( fileMapping ) + pDosHeader->e_lfanew );

	if ( isPeAndExportTableValid( pNtHeader ) )
	{
		parseExportTable( moduleInfo, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( 
			reinterpret_cast<DWORD_PTR>( fileMapping ) + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress ), 
			reinterpret_cast<DWORD_PTR>( fileMapping ) );
	}

	UnmapViewOfFile( fileMapping );
}

inline bool ApiReader::isApiForwarded( DWORD_PTR rva, PIMAGE_NT_HEADERS pNtHeader )
{
	return rva > pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress &&
		rva < pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress +
		pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
}

void ApiReader::handleForwardedApi( DWORD_PTR vaStringPointer, char* functionNameParent, DWORD_PTR rvaParent, WORD ordinalParent, ModuleInfo* moduleParent )
{
	std::string forwardedString( reinterpret_cast<char*>( vaStringPointer ) );
	auto dotPosition = forwardedString.find( '.' );

	if ( dotPosition == std::string::npos || dotPosition >= 99 )
		return;

	std::string dllName = forwardedString.substr( 0, dotPosition );
	std::string searchFunctionName = forwardedString.substr( dotPosition + 1 );

	WORD ordinal = 0;
	if ( auto hashPosition = searchFunctionName.find( '#' ); hashPosition != std::string::npos )
	{
		ordinal = static_cast<WORD>( std::stoi( searchFunctionName.substr( hashPosition + 1 ) ) );
		searchFunctionName = searchFunctionName.substr( 0, hashPosition );
	}

	if ( !_strnicmp( dllName.c_str( ), "API-", 4 ) || !_strnicmp( dllName.c_str( ), "EXT-", 4 ) )
	{
		HMODULE hModTemp = GetModuleHandleA( dllName.c_str( ) );
		if ( !hModTemp )
			hModTemp = LoadLibraryA( dllName.c_str( ) );

		if ( !hModTemp )
		{
			LOGS_DEBUG( "handleForwardedApi :: Failed to load forwarded module %s", forwardedString.c_str( ) );
			return;
		}

		DWORD_PTR addy = reinterpret_cast<DWORD_PTR>( ordinal ?
			GetProcAddress( hModTemp, reinterpret_cast<LPCSTR>( ordinal ) ) : 
			GetProcAddress( hModTemp, searchFunctionName.c_str( ) ) );

		if ( addy )
			addApi( functionNameParent, 0, ordinalParent, addy, addy - reinterpret_cast<DWORD_PTR>( hModTemp ), true, moduleParent );

		return;
	}

	dllName += ".dll";
	std::wstring dllNameW = std::wstring( dllName.begin( ), dllName.end( ) );

	ModuleInfo* module = ( !_wcsicmp( dllNameW.c_str( ), moduleParent->getFilename( ) ) ) ? moduleParent : findModuleByName( dllNameW.data( ) );

	if ( module )
	{
		DWORD_PTR vaApi = 0, rvaApi = 0;
		if ( ordinal )
			findApiByModuleAndOrdinal( module, ordinal, &vaApi, &rvaApi );
		else
			findApiByModuleAndName( module, searchFunctionName.data( ), &vaApi, &rvaApi );

		if ( rvaApi != 0 )
			addApi( functionNameParent, 0, ordinalParent, vaApi, rvaApi, true, moduleParent );
		else
			LOGS_DEBUG( "handleForwardedApi :: Api not found, this is really BAD! %s", forwardedString.c_str( ) );
	}
}

ModuleInfo* ApiReader::findModuleByName( WCHAR* name )
{
	for ( unsigned int i = 0; i < moduleList.size( ); i++ ) {

		if ( !_wcsicmp( moduleList[ i ].getFilename( ), name ) )
			return &moduleList[ i ];
	}

	return 0;
}

void ApiReader::addApiWithoutName( WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo* moduleInfo )
{
	addApi( 0, 0, ordinal, va, rva, isForwarded, moduleInfo );
}

void ApiReader::addApi( char* functionName, WORD hint, WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo* moduleInfo )
{
	ApiInfo* apiInfo = new ApiInfo( );

	if ( ( functionName != 0 ) && ( strlen( functionName ) < _countof( apiInfo->name ) ) )
	{
		strcpy_s( apiInfo->name, functionName );
	}
	else
	{
		apiInfo->name[ 0 ] = 0x00;
	}

	apiInfo->ordinal = ordinal;
	apiInfo->isForwarded = isForwarded;
	apiInfo->module = moduleInfo;
	apiInfo->rva = rva;
	apiInfo->va = va;
	apiInfo->hint = hint;

	setMinMaxApiAddress( va );

	moduleInfo->apiList.push_back( apiInfo );

	apiList.insert( API_Pair( va, apiInfo ) );
}

BYTE* ApiReader::getHeaderFromProcess( ModuleInfo* module )
{
	DWORD readSize = min( module->modBaseSize, static_cast<DWORD>( PE_HEADER_BYTES_COUNT ) );
	auto bufferHeader = std::make_unique<BYTE[ ]>( readSize );

	if ( !readMemoryFromProcess( module->modBaseAddr, readSize, bufferHeader.get( ) ) )
	{
		LOGS_DEBUG( "getHeaderFromProcess :: Error reading header" );

		return nullptr;
	}

	return bufferHeader.release( );
}

BYTE* ApiReader::getExportTableFromProcess( ModuleInfo* module, PIMAGE_NT_HEADERS pNtHeader )
{
	DWORD readSize = pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

	if ( readSize < ( sizeof( IMAGE_EXPORT_DIRECTORY ) + 8 ) )
	{
		LOGS_DEBUG( "Something is wrong with the PE Header here Export table size %d", readSize );
		readSize = sizeof( IMAGE_EXPORT_DIRECTORY ) + 100;
	}

	auto bufferExportTable = std::make_unique<BYTE[ ]>( readSize );

	if ( !readMemoryFromProcess( module->modBaseAddr + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, readSize, bufferExportTable.get( ) ) )
	{
		LOGS_DEBUG( "getExportTableFromProcess :: Error reading export table from process" );

		return nullptr;
	}

	return bufferExportTable.release( );
}

void ApiReader::parseModuleWithProcess( ModuleInfo* module )
{
	PeParser peParser( module->modBaseAddr, false );

	if ( !peParser.isValidPeFile( ) )
		return;

	auto pNtHeader = peParser.getCurrentNtHeader( );

	if ( peParser.hasExportDirectory( ) )
	{
		auto bufferExportTable = getExportTableFromProcess( module, pNtHeader );

		if ( bufferExportTable )
		{
			parseExportTable( module, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( bufferExportTable ), 
				reinterpret_cast<DWORD_PTR>( bufferExportTable ) - pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
			delete[ ] bufferExportTable;
		}
	}
}

void ApiReader::parseExportTable( ModuleInfo* module, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress )
{
	auto addressOfFunctionsArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfFunctions ) + deltaAddress );
	auto addressOfNamesArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNames ) + deltaAddress );
	auto addressOfNameOrdinalsArray = reinterpret_cast<WORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNameOrdinals ) + deltaAddress );

	LOGS_DEBUG( "parseExportTable :: module %s NumberOfNames %X", module->fullPath, pExportDir->NumberOfNames );

	for ( WORD i = 0; i < pExportDir->NumberOfNames; i++ )
	{
		auto functionName = reinterpret_cast<char*>( addressOfNamesArray[ i ] + deltaAddress );
		auto ordinal = static_cast<WORD>( addressOfNameOrdinalsArray[ i ] + pExportDir->Base );
		auto RVA = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ];
		auto VA = RVA + module->modBaseAddr;

		LOGS_DEBUG( "parseExportTable :: api %s ordinal %d imagebase " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " VA " PRINTF_DWORD_PTR_FULL_S, functionName, ordinal, module->modBaseAddr, RVA, VA );

		if ( !isApiBlacklisted( functionName ) )
		{
			if ( !isApiForwarded( RVA, pNtHeader ) )
			{
				addApi( functionName, i, ordinal, VA, RVA, false, module );
			}
			else
			{
				handleForwardedApi( RVA + deltaAddress, functionName, RVA, ordinal, module );
			}
		}
	}

	// Exports without name
	if ( pExportDir->NumberOfNames != pExportDir->NumberOfFunctions )
	{
		for ( WORD i = 0; i < pExportDir->NumberOfFunctions; i++ )
		{
			bool withoutName = true;
			for ( WORD j = 0; j < pExportDir->NumberOfNames; j++ )
			{
				if ( addressOfNameOrdinalsArray[ j ] == i )
				{
					withoutName = false;
					break;
				}
			}
			if ( withoutName && addressOfFunctionsArray[ i ] != 0 )
			{
				auto ordinal = static_cast<WORD>( i + pExportDir->Base );
				auto RVA = addressOfFunctionsArray[ i ];
				auto VA = RVA + module->modBaseAddr;

				if ( !isApiForwarded( RVA, pNtHeader ) )
				{
					addApiWithoutName( ordinal, VA, RVA, false, module );
				}
				else
				{
					handleForwardedApi( RVA + deltaAddress, nullptr, RVA, ordinal, module );
				}
			}
		}
	}
}

void ApiReader::findApiByModuleAndOrdinal( ModuleInfo* module, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	findApiByModule( module, 0, ordinal, vaApi, rvaApi );
}

void ApiReader::findApiByModuleAndName( ModuleInfo* module, char* searchFunctionName, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	findApiByModule( module, searchFunctionName, 0, vaApi, rvaApi );
}

void ApiReader::findApiByModule( ModuleInfo* module, char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi ) {
	if ( isModuleLoadedInOwnProcess( module ) ) {
		HMODULE hModule = GetModuleHandle( module->getFilename( ) );

		if ( hModule && vaApi ) {
			FARPROC procAddress = ordinal ? GetProcAddress( hModule, reinterpret_cast<LPCSTR>( static_cast<size_t>( ordinal ) ) ) : GetProcAddress( hModule, searchFunctionName );
			if ( procAddress ) {
				*vaApi = reinterpret_cast<DWORD_PTR>( procAddress );
				*rvaApi = *vaApi - reinterpret_cast<DWORD_PTR>( hModule );
				*vaApi += module->modBaseAddr;
			}
		}
		else {
			LOGS_DEBUG( "findApiByModule :: vaApi or hModule is NULL, should never happen %s", searchFunctionName ? searchFunctionName : "" );
		}
	}
	else {
		// Search API in external process
		findApiInProcess( module, searchFunctionName, ordinal, vaApi, rvaApi );
	}
}

bool ApiReader::isModuleLoadedInOwnProcess( ModuleInfo* module ) {
	return std::any_of( ownModuleList.begin( ), ownModuleList.end( ), [ module ]( const ModuleInfo& ownModule ) {
		return _wcsicmp( module->fullPath, ownModule.fullPath ) == 0;
		} );
}

void ApiReader::parseModuleWithOwnProcess( ModuleInfo* module ) {

	HMODULE hModule = GetModuleHandle( module->getFilename( ) );

	if ( hModule ) {
		auto* pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( hModule );
		auto* pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<DWORD_PTR>( hModule ) + pDosHeader->e_lfanew );

		if ( isPeAndExportTableValid( pNtHeader ) ) {
			auto* pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( reinterpret_cast<DWORD_PTR>( hModule ) + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
			parseExportTable( module, pNtHeader, pExportDir, reinterpret_cast<DWORD_PTR>( hModule ) );
		}
	}
	else {
		LOGS_DEBUG( "parseModuleWithOwnProcess :: hModule is NULL" );
	}
}

bool ApiReader::isPeAndExportTableValid( PIMAGE_NT_HEADERS pNtHeader ) {
	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE ) {
		LOGS( "-> IMAGE_NT_SIGNATURE doesn't match." );
		return false;
	}
	else if ( pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress == 0 ||
		pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size == 0 ) {
		LOGS( "-> No export table." );
		return false;
	}
	return true;
}

void ApiReader::findApiInProcess( ModuleInfo* module, char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi ) {

	auto* bufferHeader = getHeaderFromProcess( module );
	if ( !bufferHeader ) return;

	auto* pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( bufferHeader );
	auto* pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<DWORD_PTR>( bufferHeader ) + pDosHeader->e_lfanew );

	if ( isPeAndExportTableValid( pNtHeader ) ) {
		auto* bufferExportTable = getExportTableFromProcess( module, pNtHeader );
		if ( bufferExportTable ) {
			findApiInExportTable( module, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( bufferExportTable ), reinterpret_cast<DWORD_PTR>( bufferExportTable ) - pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, searchFunctionName, ordinal, vaApi, rvaApi );
			delete[ ] bufferExportTable;
		}
	}

	delete[ ] bufferHeader;
}

bool ApiReader::findApiInExportTable( ModuleInfo* module, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress, char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi ) {

	auto* addressOfFunctionsArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfFunctions ) + deltaAddress );
	auto* addressOfNamesArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNames ) + deltaAddress );
	auto* addressOfNameOrdinalsArray = reinterpret_cast<WORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNameOrdinals ) + deltaAddress );

	if ( searchFunctionName ) {
		for ( DWORD i = 0; i < pExportDir->NumberOfNames; ++i ) {
			auto* functionName = reinterpret_cast<char*>( addressOfNamesArray[ i ] + deltaAddress );
			if ( strcmp( functionName, searchFunctionName ) == 0 ) {
				*rvaApi = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ];
				*vaApi = *rvaApi + module->modBaseAddr;
				return true;
			}
		}
	}
	else {
		for ( DWORD i = 0; i < pExportDir->NumberOfFunctions; ++i ) {
			if ( ordinal == ( i + pExportDir->Base ) ) {
				*rvaApi = addressOfFunctionsArray[ i ];
				*vaApi = *rvaApi + module->modBaseAddr;
				return true;
			}
		}
	}

	return false;
}

void ApiReader::setModulePriority( ModuleInfo* module )
{
	const WCHAR* moduleFileName = module->getFilename( );

	//imports by kernelbase don't exist
	if ( !_wcsicmp( moduleFileName, L"kernelbase.dll" ) )
	{
		module->priority = -1;
	}
	else if ( !_wcsicmp( moduleFileName, L"ntdll.dll" ) )
	{
		module->priority = 0;
	}
	else if ( !_wcsicmp( moduleFileName, L"shlwapi.dll" ) )
	{
		module->priority = 0;
	}
	else if ( !_wcsicmp( moduleFileName, L"ShimEng.dll" ) )
	{
		module->priority = 0;
	}
	else if ( !_wcsicmp( moduleFileName, L"kernel32.dll" ) )
	{
		module->priority = 2;
	}
	else if ( !_wcsnicmp( moduleFileName, L"API-", 4 ) || !_wcsnicmp( moduleFileName, L"EXT-", 4 ) ) //API_SET_PREFIX_NAME, API_SET_EXTENSION
	{
		module->priority = 0;
	}
	else
	{
		module->priority = 1;
	}
}

bool ApiReader::isApiAddressValid( DWORD_PTR virtualAddress )
{
	return apiList.count( virtualAddress ) > 0;
}

ApiInfo* ApiReader::getApiByVirtualAddress( DWORD_PTR virtualAddress, bool* isSuspect ) {
	size_t countDuplicates = apiList.count( virtualAddress );
	*isSuspect = false;

	if ( countDuplicates == 0 ) {
		return nullptr;
	}

	auto range = apiList.equal_range( virtualAddress );
	if ( countDuplicates == 1 ) {
		return range.first->second;
	}

	*isSuspect = true;
	ApiInfo* apiFound = getScoredApi( range.first, countDuplicates, true, false, false, true, false, false, false, false );

	if ( !apiFound ) {
		LOGS( "getApiByVirtualAddress :: There is an API resolving bug, VA: " PRINTF_DWORD_PTR_FULL_S, virtualAddress );
	}

	return apiFound;
}

ApiInfo* ApiReader::getScoredApi( std::unordered_map<DWORD_PTR, ApiInfo*>::iterator it, size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll, bool hasPrio0Dll, bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin ) {
	ApiInfo* foundMatchingApi = nullptr;
	int countFoundApis = 0;

	for ( size_t c = 0; c < countDuplicates; ++c, ++it ) {
		ApiInfo* foundApi = it->second;
		int scoreValue = 0;

		if ( hasName && foundApi->name[ 0 ] != '\0' ) {
			++scoreValue;
			size_t apiNameLength = strlen( foundApi->name );
			if ( hasUnicodeAnsiName && ( foundApi->name[ apiNameLength - 1 ] == 'W' || foundApi->name[ apiNameLength - 1 ] == 'A' ) ) {
				++scoreValue;
			}
			if ( hasNoUnderlineInName && !strchr( foundApi->name, '_' ) ) {
				++scoreValue;
			}
		}

		int priority = foundApi->module->priority;
		if ( ( hasPrioDll && priority >= 1 ) || ( hasPrio0Dll && priority == 0 ) || ( hasPrio1Dll && priority == 1 ) || ( hasPrio2Dll && priority == 2 ) ) {
			++scoreValue;
		}

		if ( scoreValue > 0 ) {
			foundMatchingApi = foundApi;
			++countFoundApis;
			if ( firstWin ) {
				break;
			}
		}
	}

	return ( countFoundApis == 1 ) ? foundMatchingApi : nullptr;
}

void ApiReader::setMinMaxApiAddress( DWORD_PTR virtualAddress ) {
	if ( virtualAddress == 0 || virtualAddress == static_cast<DWORD_PTR>( -1 ) )
		return;

	LOGS_DEBUG( "virtualAddress %p < minApiAddress %p", virtualAddress, minApiAddress );

	minApiAddress = min( minApiAddress, virtualAddress - 1 );
	maxApiAddress = max( maxApiAddress, virtualAddress + 1 );
}

void ApiReader::readAndParseIAT( DWORD_PTR addressIAT, DWORD sizeIAT, std::map<DWORD_PTR, ImportModuleThunk>& moduleListNew ) {

	moduleThunkList = &moduleListNew;

	auto dataIat = std::make_unique<BYTE[ ]>( sizeIAT );

	if ( readMemoryFromProcess( addressIAT, sizeIAT, dataIat.get( ) ) ) {
		parseIAT( addressIAT, dataIat.get( ), sizeIAT );
	}
	else {
		LOGS_DEBUG( "ApiReader::readAndParseIAT :: error reading iat " PRINTF_DWORD_PTR_FULL_S, addressIAT );
	}
}

void ApiReader::parseIAT( DWORD_PTR addressIAT, BYTE* iatBuffer, SIZE_T size ) {

	ApiInfo* apiFound = nullptr;

	ModuleInfo* module = nullptr;

	bool isSuspect = false;

	int countApiFound = 0, countApiNotFound = 0;

	auto pIATAddress = reinterpret_cast<DWORD_PTR*>( iatBuffer );

	SIZE_T sizeIAT = size / sizeof( DWORD_PTR );

	for ( SIZE_T i = 0; i < sizeIAT; ++i ) {

		if ( !isInvalidMemoryForIat( pIATAddress[ i ] ) ) {

			LOGS_DEBUG( "min %p max %p address %p", minApiAddress, maxApiAddress, pIATAddress[ i ] );

			if ( pIATAddress[ i ] > minApiAddress && pIATAddress[ i ] < maxApiAddress ) {

				apiFound = getApiByVirtualAddress( pIATAddress[ i ], &isSuspect );

				LOGS_DEBUG( "apiFound %p address %p", apiFound, pIATAddress[ i ] );

				if ( !apiFound ) {
					LOGS( "getApiByVirtualAddress :: No Api found " PRINTF_DWORD_PTR_FULL_S, pIATAddress[ i ] );
				}
				else if ( apiFound != reinterpret_cast<ApiInfo*>( 1 ) ) {
					++countApiFound;
					LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " %ls %d %s", apiFound->va, apiFound->module->getFilename( ), apiFound->ordinal, apiFound->name );

					if ( module != apiFound->module ) {
						module = apiFound->module;
						addFoundApiToModuleList( addressIAT + reinterpret_cast<DWORD_PTR>( &pIATAddress[ i ] ) - reinterpret_cast<DWORD_PTR>( iatBuffer ), apiFound, true, isSuspect );
					}
					else {
						addFoundApiToModuleList( addressIAT + reinterpret_cast<DWORD_PTR>( &pIATAddress[ i ] ) - reinterpret_cast<DWORD_PTR>( iatBuffer ), apiFound, false, isSuspect );
					}
				}
				else {
					++countApiNotFound;
					addNotFoundApiToModuleList( addressIAT + reinterpret_cast<DWORD_PTR>( &pIATAddress[ i ] ) - reinterpret_cast<DWORD_PTR>( iatBuffer ), pIATAddress[ i ] );
				}
			}
			else {
				++countApiNotFound;
				addNotFoundApiToModuleList( addressIAT + reinterpret_cast<DWORD_PTR>( &pIATAddress[ i ] ) - reinterpret_cast<DWORD_PTR>( iatBuffer ), pIATAddress[ i ] );
			}
		}
	}

	LOGS( "IAT parsing finished, found %d valid APIs, missed %d APIs", countApiFound, countApiNotFound );
}


void ApiReader::addFoundApiToModuleList( DWORD_PTR iatAddressVA, ApiInfo* apiFound, bool isNewModule, bool isSuspect )
{
	if ( isNewModule )
	{
		addModuleToModuleList( apiFound->module->getFilename( ), iatAddressVA - targetImageBase );
	}
	addFunctionToModuleList( apiFound, iatAddressVA, iatAddressVA - targetImageBase, apiFound->ordinal, true, isSuspect );
}

bool ApiReader::addModuleToModuleList( const WCHAR* moduleName, DWORD_PTR firstThunk )
{
	ImportModuleThunk module;

	module.firstThunk = firstThunk;
	wcscpy_s( module.moduleName, moduleName );

	( *moduleThunkList ).insert( std::pair<DWORD_PTR, ImportModuleThunk>( firstThunk, module ) );

	return true;
}

void ApiReader::addUnknownModuleToModuleList( DWORD_PTR firstThunk )
{
	ImportModuleThunk module;

	module.firstThunk = firstThunk;
	wcscpy_s( module.moduleName, L"?" );

	( *moduleThunkList ).insert( std::pair<DWORD_PTR, ImportModuleThunk>( firstThunk, module ) );
}

bool ApiReader::addFunctionToModuleList( ApiInfo* apiFound, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect )
{
	ImportThunk import;
	ImportModuleThunk* module = 0;
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;

	if ( ( *moduleThunkList ).size( ) > 1 )
	{
		iterator1 = ( *moduleThunkList ).begin( );
		while ( iterator1 != ( *moduleThunkList ).end( ) )
		{
			if ( rva >= iterator1->second.firstThunk )
			{
				iterator1++;
				if ( iterator1 == ( *moduleThunkList ).end( ) )
				{
					iterator1--;
					module = &( iterator1->second );
					break;
				}
				else if ( rva < iterator1->second.firstThunk )
				{
					iterator1--;
					module = &( iterator1->second );
					break;
				}
			}
			else
			{

				LOGS_DEBUG( "Error iterator1 != (*moduleThunkList).end()" );

				break;
			}
		}
	}
	else
	{
		iterator1 = ( *moduleThunkList ).begin( );
		module = &( iterator1->second );
	}

	if ( !module )
	{

		LOGS_DEBUG( "ImportsHandling::addFunction module not found rva " PRINTF_DWORD_PTR_FULL_S, rva );

		return false;
	}


import.suspect = suspect;
import.valid = valid;
import.va = va;
import.rva = rva;
import.apiAddressVA = apiFound->va;
import.ordinal = ordinal;
import.hint = (WORD)apiFound->hint;

	wcscpy_s( import.moduleName, apiFound->module->getFilename( ) );
	strcpy_s( import.name, apiFound->name );

	module->thunkList.insert( std::pair<DWORD_PTR, ImportThunk>( import.rva, import ) );

	return true;
}

void ApiReader::clearAll( )
{
	minApiAddress = (DWORD_PTR)-1;
	maxApiAddress = 0;

	for ( stdext::hash_map<DWORD_PTR, ApiInfo*>::iterator it = apiList.begin( ); it != apiList.end( ); ++it )
	{
		delete it->second;
	}
	apiList.clear( );

	if ( moduleThunkList != 0 )
	{
		( *moduleThunkList ).clear( );
	}
}

bool ApiReader::addNotFoundApiToModuleList( DWORD_PTR iatAddressVA, DWORD_PTR apiAddress )
{
	ImportThunk import;
	ImportModuleThunk* module = 0;
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	DWORD_PTR rva = iatAddressVA - targetImageBase;

	if ( ( *moduleThunkList ).size( ) > 0 )
	{
		iterator1 = ( *moduleThunkList ).begin( );
		while ( iterator1 != ( *moduleThunkList ).end( ) )
		{
			if ( rva >= iterator1->second.firstThunk )
			{
				iterator1++;
				if ( iterator1 == ( *moduleThunkList ).end( ) )
				{
					iterator1--;
					//new unknown module
					if ( iterator1->second.moduleName[ 0 ] == L'?' )
					{
						module = &( iterator1->second );
					}
					else
					{
						addUnknownModuleToModuleList( rva );
						module = &( ( *moduleThunkList ).find( rva )->second );
					}

					break;
				}
				else if ( rva < iterator1->second.firstThunk )
				{
					iterator1--;
					module = &( iterator1->second );
					break;
				}
			}
			else
			{

				LOGS_DEBUG( "Error iterator1 != (*moduleThunkList).end()\r\n" );

				break;
			}
		}
	}
	else
	{
		//new unknown module
		addUnknownModuleToModuleList( rva );
		module = &( ( *moduleThunkList ).find( rva )->second );
	}

	if ( !module )
	{

		LOGS_DEBUG( "ImportsHandling::addFunction module not found rva " PRINTF_DWORD_PTR_FULL_S, rva );

		return false;
	}


import.suspect = true;
import.valid = false;
import.va = iatAddressVA;
import.rva = rva;
import.apiAddressVA = apiAddress;
import.ordinal = 0;

	wcscpy_s( import.moduleName, L"?" );
	strcpy_s( import.name, "?" );

	module->thunkList.insert( std::pair<DWORD_PTR, ImportThunk>( import.rva, import ) );

	return true;
}

bool ApiReader::isApiBlacklisted( const char* functionName )
{
	if ( SystemInformation::currenOS < WIN_VISTA_32 )
	{
		if ( !strcmp( functionName, "RestoreLastError" ) )
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}


	/*#ifdef _WIN64
	else if (SystemInformation::currenOS == WIN_XP_64 && !strcmp(functionName, "DecodePointer"))
	{
		return true;
	}
*/
}

bool ApiReader::isWinSxSModule( ModuleInfo* module )
{
	if ( wcsstr( module->fullPath, L"\\WinSxS\\" ) )
	{
		return true;
	}
	else if ( wcsstr( module->fullPath, L"\\winsxs\\" ) )
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool ApiReader::isInvalidMemoryForIat( DWORD_PTR address )
{
	if ( address == 0 )
		return true;

	if ( address == -1 )
		return true;

	MEMORY_BASIC_INFORMATION memBasic = { 0 };

	if ( VirtualQueryEx( ProcessAccessHelp::hProcess, (LPCVOID)address, &memBasic, sizeof( MEMORY_BASIC_INFORMATION ) ) )
	{
		if ( ( memBasic.State == MEM_COMMIT ) && ProcessAccessHelp::isPageAccessable( memBasic.Protect ) )
		{
			return false;
		}
		else
		{
			return true;
		}
	}
	else
	{
		return true;
	}
}
