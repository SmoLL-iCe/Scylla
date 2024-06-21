
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

stdext::hash_multimap<DWORD_PTR, ApiInfo*> ApiReader::apiList; //api look up table
std::map<DWORD_PTR, ImportModuleThunk>* ApiReader::moduleThunkList; //store found apis

DWORD_PTR ApiReader::minApiAddress = static_cast<DWORD_PTR>( - 1);
DWORD_PTR ApiReader::maxApiAddress = 0;

void ApiReader::readApisFromModuleList( )
{
	readExportTableAlwaysFromDisk = Config::APIS_ALWAYS_FROM_DISK;

	for ( auto& pModule : moduleList )
	{
		setModulePriority( &pModule );

		if ( pModule.modBaseAddr + pModule.modBaseSize > maxValidAddress )
		{
			maxValidAddress = pModule.modBaseAddr + pModule.modBaseSize;
		}

		LOGS_DEBUG( "Module parsing: %ls", pModule.fullPath );

		if ( !pModule.isAlreadyParsed )
		{
			parseModule( &pModule );
		}
	}

	LOGS( "Address Min " PRINTF_DWORD_PTR_FULL_S " Max " PRINTF_DWORD_PTR_FULL_S "\nimagebase " PRINTF_DWORD_PTR_FULL_S " maxValidAddress " PRINTF_DWORD_PTR_FULL_S, 
		minApiAddress, maxApiAddress, targetImageBase, maxValidAddress );
}

void ApiReader::parseModule( ModuleInfo* pModule )
{
	pModule->parsing = true;

	if ( isWinSxSModule( pModule ) || ( readExportTableAlwaysFromDisk && !isModuleLoadedInOwnProcess( pModule ) ) )
	{
		parseModuleWithMapping( pModule );
	}
	else if ( isModuleLoadedInOwnProcess( pModule ) )
	{
		parseModuleWithOwnProcess( pModule );
	}
	else
	{
		parseModuleWithProcess( pModule );
	}

	pModule->isAlreadyParsed = true;
}

void ApiReader::parseModuleWithMapping( ModuleInfo* moduleInfo )
{
	LPVOID fileMapping = createFileMappingViewRead( moduleInfo->fullPath );

	if ( fileMapping == nullptr )
		return;

	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( fileMapping );
	auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<DWORD_PTR>( fileMapping ) + pDosHeader->e_lfanew );

	if ( isPeAndExportTableValid( pNtHeader ) )
	{
		parseExportTable( moduleInfo, pNtHeader, 
			reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( 
			reinterpret_cast<DWORD_PTR>( fileMapping ) + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress ), 
			reinterpret_cast<DWORD_PTR>( fileMapping ) );
	}

	UnmapViewOfFile( fileMapping );
}

inline bool ApiReader::isApiForwarded( DWORD_PTR rva, PIMAGE_NT_HEADERS pNtHeader )
{
	auto DirExport = pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	return ( rva > DirExport.VirtualAddress )
		&& ( rva < ( DirExport.VirtualAddress + DirExport.Size ) );
}

void ApiReader::handleForwardedApi(DWORD_PTR vaStringPointer, const char* functionNameParent, DWORD_PTR rvaParent, WORD ordinalParent, ModuleInfo* moduleParent) {
   
	auto forwardedString = reinterpret_cast<char*>(vaStringPointer);

    WORD ordinal = 0;
    DWORD_PTR vaApi = 0;
    DWORD_PTR rvaApi = 0;

    auto pos = std::strchr(forwardedString, '.');

    if (!pos) 
		return;

	std::string dllName;

    dllName.assign(forwardedString, pos);

	std::string searchFunctionName = pos + 1;

    if (auto hashPos = std::strchr(searchFunctionName.c_str(), '#')) {
        searchFunctionName = hashPos + 1;
        ordinal = static_cast<WORD>(std::atoi(searchFunctionName.c_str()));
    }

    if (!_strnicmp(dllName.c_str(), "API-", 4) || !_strnicmp(dllName.c_str(), "EXT-", 4)) {
        HMODULE hModTemp = GetModuleHandleA(dllName.c_str());
        if (!hModTemp) {
            hModTemp = LoadLibraryA(dllName.c_str());
        }

		if ( !hModTemp ) {
			return;
		}

        FARPROC addy = ordinal ? GetProcAddress(hModTemp, reinterpret_cast<LPCSTR>(ordinal)) : GetProcAddress(hModTemp, searchFunctionName.c_str());

        if (addy) {
            addApi(functionNameParent, 0, ordinalParent, reinterpret_cast<DWORD_PTR>(addy), reinterpret_cast<DWORD_PTR>(addy) - reinterpret_cast<DWORD_PTR>(hModTemp), true, moduleParent);
        }
        return;
    }

    dllName += ".dll";

    std::wstring dllNameW(dllName.begin(), dllName.end());

	ModuleInfo* pModule = ( !_wcsicmp( dllNameW.c_str( ), moduleParent->getFilename( ) ) ) ? moduleParent : findModuleByName( dllNameW.c_str( ) );

    if (pModule) {

        if (ordinal) {

            findApiByModuleAndOrdinal(pModule, ordinal, &vaApi, &rvaApi);

        } else {

            findApiByModuleAndName(pModule, searchFunctionName.c_str(), &vaApi, &rvaApi);
        }

        if (rvaApi == 0) {
            LOGS("handleForwardedApi :: Api not found, this is really BAD! %s", forwardedString);
        } else {
            addApi(functionNameParent, 0, ordinalParent, vaApi, rvaApi, true, moduleParent);
        }
    }
}

ModuleInfo* ApiReader::findModuleByName( const WCHAR* name )
{
	for ( unsigned int i = 0; i < moduleList.size( ); i++ ) {
		if ( !_wcsicmp( moduleList[ i ].getFilename( ), name ) )
		{
			return &moduleList[ i ];
		}
	}

	return 0;
}

void ApiReader::addApiWithoutName( WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo* moduleInfo )
{
	addApi( 0, 0, ordinal, va, rva, isForwarded, moduleInfo );
}

void ApiReader::addApi( const char* functionName, WORD hint, WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo* moduleInfo )
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

std::unique_ptr<BYTE[ ]> ApiReader::getHeaderFromProcess( ModuleInfo* pModule ) {

	DWORD readSize = std::min( pModule->modBaseSize, static_cast<DWORD>( PE_HEADER_BYTES_COUNT ) );

	auto bufferHeader = std::make_unique<BYTE[ ]>( readSize );

	if ( !readMemoryFromProcess( pModule->modBaseAddr, readSize, bufferHeader.get( ) ) ) {

		LOGS( "getHeaderFromProcess :: Error reading header" );

		return nullptr;
	}

	return bufferHeader;
}

std::unique_ptr<BYTE[ ]> ApiReader::getExportTableFromProcess( ModuleInfo* pModule, PIMAGE_NT_HEADERS pNtHeader ) {

	DWORD readSize = pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

	if ( readSize < ( sizeof( IMAGE_EXPORT_DIRECTORY ) + 8 ) ) {

		LOGS( "Something is wrong with the PE Header here Export table size %d", readSize );

		readSize = sizeof( IMAGE_EXPORT_DIRECTORY ) + 100;
	}

	if ( readSize == 0 ) return nullptr;

	auto bufferExportTable = std::make_unique<BYTE[ ]>( readSize );

	if ( !readMemoryFromProcess( 
		pModule->modBaseAddr + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, 
		readSize, bufferExportTable.get( ) ) ) {

		LOGS( "getExportTableFromProcess :: Error reading export table from process" );

		return nullptr;
	}
	return bufferExportTable;
}

void ApiReader::parseModuleWithProcess( ModuleInfo* pModule )
{
	PeParser peParser( pModule->modBaseAddr, false );

	if ( !peParser.isValidPeFile( ) )
		return;

	auto pNtHeader = peParser.getCurrentNtHeader( );

	if ( peParser.hasExportDirectory( ) )
	{
		auto bufferExportTable = getExportTableFromProcess( pModule, pNtHeader );

		if ( bufferExportTable )
		{
			parseExportTable( pModule, pNtHeader, 
				reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( bufferExportTable.get( ) ), 
				reinterpret_cast<DWORD_PTR>( bufferExportTable.get( ) ) - pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
		}
	}
}

void ApiReader::parseExportTable( ModuleInfo* pModule, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress )
{
	auto addressOfFunctionsArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfFunctions ) + deltaAddress );
	auto addressOfNamesArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNames ) + deltaAddress );
	auto addressOfNameOrdinalsArray = reinterpret_cast<WORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNameOrdinals ) + deltaAddress );

	LOGS( "parseExportTable :: pModule %ls NumberOfNames %X", pModule->fullPath, pExportDir->NumberOfNames );

	for ( WORD i = 0; i < pExportDir->NumberOfNames; i++ )
	{
		auto functionName = reinterpret_cast<char*>( addressOfNamesArray[ i ] + deltaAddress );
		WORD ordinal = static_cast<WORD>( addressOfNameOrdinalsArray[ i ] + pExportDir->Base );
		DWORD_PTR RVA = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ];
		DWORD_PTR VA = RVA + pModule->modBaseAddr;

		LOGS( "parseExportTable :: api %s ordinal %d imagebase " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " VA " PRINTF_DWORD_PTR_FULL_S, functionName, ordinal, pModule->modBaseAddr, RVA, VA );

		if ( !isApiBlacklisted( functionName ) )
		{
			if ( !isApiForwarded( RVA, pNtHeader ) )
			{
				addApi( functionName, i, ordinal, VA, RVA, false, pModule );
			}
			else
			{
				handleForwardedApi( RVA + deltaAddress, functionName, RVA, ordinal, pModule );
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
				WORD ordinal = static_cast<WORD>( i + pExportDir->Base );
				DWORD_PTR RVA = addressOfFunctionsArray[ i ];
				DWORD_PTR VA = RVA + pModule->modBaseAddr;

				if ( !isApiForwarded( RVA, pNtHeader ) )
				{
					addApiWithoutName( ordinal, VA, RVA, false, pModule );
				}
				else
				{
					handleForwardedApi( RVA + deltaAddress, nullptr, RVA, ordinal, pModule );
				}
			}
		}
	}
}

void ApiReader::findApiByModuleAndOrdinal( ModuleInfo* pModule, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	findApiByModule( pModule, 0, ordinal, vaApi, rvaApi );
}

void ApiReader::findApiByModuleAndName( ModuleInfo* pModule, const char* searchFunctionName, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	findApiByModule( pModule, searchFunctionName, 0, vaApi, rvaApi );
}

void ApiReader::findApiByModule( ModuleInfo* pModule, const char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi ) {
	if ( isModuleLoadedInOwnProcess( pModule ) ) {
		HMODULE hModule = GetModuleHandle( pModule->getFilename( ) );

		if ( hModule ) {
			if ( vaApi ) {
				FARPROC procAddress = ordinal ? GetProcAddress( hModule, MAKEINTRESOURCEA( ordinal ) ) : GetProcAddress( hModule, searchFunctionName );
				if ( procAddress ) {
					*vaApi = reinterpret_cast<DWORD_PTR>( procAddress );
					*rvaApi = *vaApi - reinterpret_cast<DWORD_PTR>( hModule );
					*vaApi = *rvaApi + pModule->modBaseAddr;
				}
			}
			else {
				LOGS( "findApiByModule :: vaApi == nullptr, should never happen %s", searchFunctionName );
			}
		}
		else {
			LOGS( "findApiByModule :: hModule == nullptr, should never happen %ls", pModule->getFilename( ) );
		}
	}
	else {
		// Search API in external process
		findApiInProcess( pModule, searchFunctionName, ordinal, vaApi, rvaApi );
	}
}

bool ApiReader::isModuleLoadedInOwnProcess( ModuleInfo* pModule ) {
	for ( const auto& module : ownModuleList ) {
		if ( !_wcsicmp( pModule->fullPath, module.fullPath ) ) {
			return true;
		}
	}
	return false;
}

void ApiReader::parseModuleWithOwnProcess( ModuleInfo* pModule ) {
	HMODULE hModule = GetModuleHandle( pModule->getFilename( ) );

	if ( hModule ) {
		auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( hModule );
		auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<DWORD_PTR>( hModule ) + pDosHeader->e_lfanew );

		if ( isPeAndExportTableValid( pNtHeader ) ) {
			parseExportTable( pModule, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( reinterpret_cast<DWORD_PTR>( hModule ) + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress ), reinterpret_cast<DWORD_PTR>( hModule ) );
		}
	}
	else {
		LOGS( "parseModuleWithOwnProcess :: hModule is nullptr" );
	}
}

bool ApiReader::isPeAndExportTableValid( PIMAGE_NT_HEADERS pNtHeader ) {
	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE ) {
		LOGS_DEBUG( "-> IMAGE_NT_SIGNATURE doesn't match." );
		return false;
	}
	else if ( pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress == 0 || pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size == 0 ) {
		LOGS_DEBUG( "-> No export table." );
		return false;
	}

	return true;
}

void ApiReader::findApiInProcess( ModuleInfo* pModule, const char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	std::unique_ptr<BYTE[ ]> bufferHeader = getHeaderFromProcess( pModule );

	if ( !bufferHeader )
		return;

	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( bufferHeader.get( ) );
	auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<DWORD_PTR>( bufferHeader.get( ) ) + pDosHeader->e_lfanew );

	if ( isPeAndExportTableValid( pNtHeader ) )
	{
		std::unique_ptr<BYTE[ ]> bufferExportTable = getExportTableFromProcess( pModule, pNtHeader );

		if ( bufferExportTable )
		{
			findApiInExportTable( pModule, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( bufferExportTable.get( ) ), 
				reinterpret_cast<DWORD_PTR>( bufferExportTable.get( ) ) - pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, searchFunctionName, ordinal, vaApi, rvaApi );
		}
	}
}

bool ApiReader::findApiInExportTable( ModuleInfo* pModule, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress, const char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	auto addressOfFunctionsArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfFunctions ) + deltaAddress );
	auto addressOfNamesArray = reinterpret_cast<DWORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNames ) + deltaAddress );
	auto addressOfNameOrdinalsArray = reinterpret_cast<WORD*>( static_cast<DWORD_PTR>( pExportDir->AddressOfNameOrdinals ) + deltaAddress );

	if ( searchFunctionName )
	{
		for ( DWORD i = 0; i < pExportDir->NumberOfNames; i++ )
		{
			auto functionName = reinterpret_cast<char*>( addressOfNamesArray[ i ] + deltaAddress );

			if ( !strcmp( functionName, searchFunctionName ) )
			{
				*rvaApi = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ];
				*vaApi = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ] + pModule->modBaseAddr;
				return true;
			}
		}
	}
	else
	{
		for ( DWORD i = 0; i < pExportDir->NumberOfFunctions; i++ )
		{
			if ( ordinal == ( i + pExportDir->Base ) )
			{
				*rvaApi = addressOfFunctionsArray[ i ];
				*vaApi = addressOfFunctionsArray[ i ] + pModule->modBaseAddr;
				return true;
			}
		}
	}

	return false;
}

void ApiReader::setModulePriority( ModuleInfo* pModule ) {
	const WCHAR* moduleFileName = pModule->getFilename( );

	if ( !_wcsicmp( moduleFileName, L"kernelbase.dll" ) ) {
		pModule->priority = -1;
	}
	else if ( !_wcsicmp( moduleFileName, L"ntdll.dll" ) 
		|| !_wcsicmp( moduleFileName, L"shlwapi.dll" ) 
		|| !_wcsicmp( moduleFileName, L"ShimEng.dll" ) 
		|| !_wcsnicmp( moduleFileName, L"API-", 4 ) 
		|| !_wcsnicmp( moduleFileName, L"EXT-", 4 ) ) {
		pModule->priority = 0;
	}
	else if ( !_wcsicmp( moduleFileName, L"kernel32.dll" ) ) {
		pModule->priority = 2;
	}
	else {
		pModule->priority = 1;
	}
}

bool ApiReader::isApiAddressValid( DWORD_PTR virtualAddress )
{
	return apiList.count( virtualAddress ) > 0;
}

ApiInfo* ApiReader::getApiByVirtualAddress( DWORD_PTR virtualAddress, bool* isSuspect ) {

	*isSuspect = false;
	auto range = apiList.equal_range( virtualAddress );

	size_t countDuplicates = std::distance( range.first, range.second );

	if ( countDuplicates == 0 ) {
		return nullptr;
	}
	else if ( countDuplicates == 1 ) {
		// API is 100% correct
		return range.first->second;
	}
	else {
		auto& it = range.first;

		// any high priority with a name
		auto apiFound = getScoredApi( it, countDuplicates, true, false, false, true, false, false, false, false );
		if ( apiFound ) return apiFound;

		*isSuspect = true;

		// high priority with a name and ansi/unicode name
		apiFound = getScoredApi( it, countDuplicates, true, true, false, true, false, false, false, false );
		if ( apiFound ) return apiFound;

		// priority 2 with no underline in name
		apiFound = getScoredApi( it, countDuplicates, true, false, true, false, false, false, true, false );
		if ( apiFound ) return apiFound;

		// priority 1 with a name
		apiFound = getScoredApi( it, countDuplicates, true, false, false, false, false, true, false, false );
		if ( apiFound ) return apiFound;

		// with a name
		apiFound = getScoredApi( it, countDuplicates, true, false, false, false, false, false, false, false );
		if ( apiFound ) return apiFound;

		// any with priority, name, ansi/unicode
		apiFound = getScoredApi( it, countDuplicates, true, true, false, true, false, false, false, true );
		if ( apiFound ) return apiFound;

		// any with priority
		apiFound = getScoredApi( it, countDuplicates, false, false, false, true, false, false, false, true );
		if ( apiFound ) return apiFound;

		// has prio 0 and name
		apiFound = getScoredApi( it, countDuplicates, false, false, false, false, true, false, false, true );
		if ( apiFound ) return apiFound;
	}

	// is never reached
	LOGS_DEBUG( "getApiByVirtualAddress :: There is an API resolving bug, VA: " PRINTF_DWORD_PTR_FULL_S, virtualAddress );

	for ( auto& it = range.first; it != range.second; ++it ) {
		auto apiFound = it->second;
		LOGS_DEBUG( "-> Possible API: %s ord: %d ", apiFound->name.c_str( ), apiFound->ordinal );
	}

	return reinterpret_cast<ApiInfo*>( 1 );
}

ApiInfo* ApiReader::getScoredApi( stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator it, size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll, bool hasPrio0Dll, bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin ) {
	ApiInfo* foundMatchingApi = nullptr;
	int countFoundApis = 0;
	int scoreNeeded = hasName + hasUnicodeAnsiName + hasNoUnderlineInName + hasPrioDll + hasPrio0Dll + hasPrio1Dll + hasPrio2Dll;

	for ( size_t i = 0; i < countDuplicates; ++i, ++it ) {
		ApiInfo* foundApi = it->second;
		int scoreValue = 0;

		if ( hasName && foundApi->name[ 0 ] != '\0' ) {
			++scoreValue;
			if ( hasUnicodeAnsiName ) {
				size_t apiNameLength = std::strlen( foundApi->name );
				if ( foundApi->name[ apiNameLength - 1 ] == 'W' || foundApi->name[ apiNameLength - 1 ] == 'A' ) {
					++scoreValue;
				}
			}
			if ( hasNoUnderlineInName && !std::strrchr( foundApi->name, '_' ) ) {
				++scoreValue;
			}
		}

		if ( hasPrioDll && foundApi->module->priority >= 1 ) ++scoreValue;
		if ( hasPrio0Dll && foundApi->module->priority == 0 ) ++scoreValue;
		if ( hasPrio1Dll && foundApi->module->priority == 1 ) ++scoreValue;
		if ( hasPrio2Dll && foundApi->module->priority == 2 ) ++scoreValue;

		if ( scoreValue == scoreNeeded ) {
			foundMatchingApi = foundApi;
			++countFoundApis;
			if ( firstWin ) return foundMatchingApi;
		}
	}

	return countFoundApis == 1 ? foundMatchingApi : nullptr;
}

void ApiReader::setMinMaxApiAddress( DWORD_PTR virtualAddress )
{
	if ( virtualAddress == 0 || virtualAddress == static_cast<DWORD_PTR>( -1 ) )
		return;

	if ( virtualAddress < minApiAddress )
	{
		LOGS( "virtualAddress %p < minApiAddress %p", virtualAddress, minApiAddress );
		minApiAddress = virtualAddress - 1;
	}
	if ( virtualAddress > maxApiAddress )
	{
		maxApiAddress = virtualAddress + 1;
	}
}

void ApiReader::readAndParseIAT( DWORD_PTR addressIAT, DWORD sizeIAT, std::map<DWORD_PTR, ImportModuleThunk>& moduleListNew )
{
	moduleThunkList = &moduleListNew;
	auto dataIat = std::make_unique<BYTE[ ]>( sizeIAT );
	if ( readMemoryFromProcess( addressIAT, sizeIAT, dataIat.get( ) ) )
	{
		parseIAT( addressIAT, dataIat.get( ), sizeIAT );
	}
	else
	{
		LOGS( "ApiReader::readAndParseIAT :: error reading iat " PRINTF_DWORD_PTR_FULL_S, addressIAT );
	}
}

void ApiReader::parseIAT( DWORD_PTR addressIAT, BYTE* iatBuffer, SIZE_T size )
{
	std::span<DWORD_PTR> iatSpan( reinterpret_cast<DWORD_PTR*>( iatBuffer ), size / sizeof( DWORD_PTR ) );

	ModuleInfo* pModule = nullptr;
	bool isSuspect = false;
	int countApiFound = 0, countApiNotFound = 0;

	for ( auto& address : iatSpan )
	{
		if ( !isInvalidMemoryForIat( address ) )
		{
			LOGS( "min %p max %p address %p", minApiAddress, maxApiAddress, address );

			if ( address > minApiAddress && address < maxApiAddress )
			{
				auto apiFound = getApiByVirtualAddress( address, &isSuspect );

				LOGS( "apiFound %p address %p", apiFound, address );

				if ( apiFound == nullptr )
				{
					LOGS_DEBUG( "getApiByVirtualAddress :: No Api found " PRINTF_DWORD_PTR_FULL_S, address );
				}
				else if ( apiFound == reinterpret_cast<ApiInfo*>( 1 ) )
				{
					LOGS( "apiFound == reinterpret_cast<ApiInfo*>( 1 ) -> " PRINTF_DWORD_PTR_FULL_S, address );
				}
				else
				{
					countApiFound++;
					LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " %ls %d %s", apiFound->va, apiFound->module->getFilename( ), apiFound->ordinal, apiFound->name );

					DWORD_PTR iatEntryAddress = addressIAT + reinterpret_cast<DWORD_PTR>( &address ) - reinterpret_cast<DWORD_PTR>( iatBuffer );
					if ( pModule != apiFound->module )
					{
						pModule = apiFound->module;
						addFoundApiToModuleList( iatEntryAddress, apiFound, true, isSuspect );
					}
					else
					{
						addFoundApiToModuleList( iatEntryAddress, apiFound, false, isSuspect );
					}
				}
			}
			else
			{
				countApiNotFound++;
				addNotFoundApiToModuleList( addressIAT + reinterpret_cast<DWORD_PTR>( &address ) - reinterpret_cast<DWORD_PTR>( iatBuffer ), address );
			}
		}
	}

	LOGS_DEBUG( "IAT parsing finished, found %d valid APIs, missed %d APIs", countApiFound, countApiNotFound );
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
	ImportModuleThunk pModule;

	pModule.firstThunk = firstThunk;
	wcscpy_s( pModule.moduleName, moduleName );

	( *moduleThunkList ).insert( std::pair<DWORD_PTR, ImportModuleThunk>( firstThunk, pModule ) );

	return true;
}

void ApiReader::addUnknownModuleToModuleList( DWORD_PTR firstThunk )
{
	ImportModuleThunk pModule;

	pModule.firstThunk = firstThunk;
	wcscpy_s( pModule.moduleName, L"?" );

	( *moduleThunkList ).insert( std::pair<DWORD_PTR, ImportModuleThunk>( firstThunk, pModule ) );
}

bool ApiReader::addFunctionToModuleList( ApiInfo* apiFound, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect ) {
	if ( !moduleThunkList || moduleThunkList->empty( ) ) {
		LOGS( "ImportsHandling::addFunction moduleThunkList is empty" );
		return false;
	}

	auto pModule = findModuleForRVA( rva );
	if ( !pModule ) {
		LOGS( "ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL_S, rva );
		return false;
	}

	ImportThunk pImport{
		.va = va,
		.rva = rva,
		.ordinal = ordinal,
		.apiAddressVA = apiFound->va,
		.hint = static_cast<WORD>( apiFound->hint ),
		.valid = valid,
		.suspect = suspect,
	};

	wcscpy_s( pImport.moduleName, apiFound->module->getFilename( ) );
	strcpy_s( pImport.name, apiFound->name );

	pModule->thunkList.insert( { pImport.rva, pImport } );

	return true;
}

bool ApiReader::addNotFoundApiToModuleList( DWORD_PTR iatAddressVA, DWORD_PTR apiAddress ) {
	if ( !moduleThunkList || moduleThunkList->empty( ) ) {
		addUnknownModuleToModuleList( iatAddressVA - targetImageBase );
	}

	DWORD_PTR rva = iatAddressVA - targetImageBase;
	auto pModule = findModuleForRVA( rva, true );

	if ( !pModule ) {
		LOGS( "ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL_S, rva );
		return false;
	}

	ImportThunk pImport{
		.moduleName = L"?",
		.name = "?",
		.va = iatAddressVA,
		.rva = rva,
		.ordinal = 0,
		.apiAddressVA = apiAddress,
		.valid = false,
		.suspect = true
	};

	pModule->thunkList.insert( { pImport.rva, pImport } );

	return true;
}

ImportModuleThunk* ApiReader::findModuleForRVA( DWORD_PTR rva, bool addUnknownModuleIfNeeded ) {
	auto it = std::find_if( moduleThunkList->begin( ), moduleThunkList->end( ),
		[ rva ]( const auto& pair ) { return rva >= pair.second.firstThunk; } );

	if ( it == moduleThunkList->end( ) || ( rva < it->second.firstThunk && it != moduleThunkList->begin( ) ) ) {
		--it; // Adjust iterator to point to the correct module
	}

	if ( it == moduleThunkList->end( ) || ( addUnknownModuleIfNeeded && it->second.moduleName[ 0 ] != L'?' ) ) {
		if ( addUnknownModuleIfNeeded ) {
			addUnknownModuleToModuleList( rva );
			return &moduleThunkList->find( rva )->second;
		}
		return nullptr;
	}

	return &it->second;
}

void ApiReader::clearAll() {
    minApiAddress = static_cast<DWORD_PTR>(-1);
    maxApiAddress = 0;

    for (auto& [key, apiInfo] : apiList) {
        delete apiInfo;
    }
    apiList.clear();

    if (moduleThunkList != nullptr) {
        moduleThunkList->clear();
    }
}

bool ApiReader::isApiBlacklisted(const char* functionName) {
    return SystemInformation::currenOS < WIN_VISTA_32 && !strcmp(functionName, "RestoreLastError");
}

bool ApiReader::isWinSxSModule(ModuleInfo* pModule) {
    const wchar_t* fullPath = pModule->fullPath;
    return wcsstr(fullPath, L"\\WinSxS\\") || wcsstr(fullPath, L"\\winsxs\\");
}

bool ApiReader::isInvalidMemoryForIat(DWORD_PTR address) {
    if (address == 0 || address == static_cast<DWORD_PTR>(-1))
        return true;

    MEMORY_BASIC_INFORMATION memBasic{};

    if (ApiTools::VirtualQueryEx(ProcessAccessHelp::hProcess, reinterpret_cast<LPVOID>(address), &memBasic, sizeof(MEMORY_BASIC_INFORMATION))) {
        return !(memBasic.State == MEM_COMMIT && ProcessAccessHelp::isPageAccessable(memBasic.Protect));
    }
    return true;
}
