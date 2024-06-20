
#include "ApiReader.h"
#include "ScyllaConfig.hpp"
#include "Architecture.h"
#include "SystemInformation.h"
#include "StringConversion.h"
#include "PeParser.h"
#include "Tools/Logs.h"

stdext::hash_multimap<DWORD_PTR, ApiInfo*> ApiReader::apiList; //api look up table
std::map<DWORD_PTR, ImportModuleThunk>* ApiReader::moduleThunkList; //store found apis

DWORD_PTR ApiReader::minApiAddress = (DWORD_PTR)-1;
DWORD_PTR ApiReader::maxApiAddress = 0;

//#define DEBUG_COMMENTS

void ApiReader::readApisFromModuleList( )
{
	readExportTableAlwaysFromDisk = Config::APIS_ALWAYS_FROM_DISK;

	for ( unsigned int i = 0; i < moduleList.size( );i++ )
	{
		setModulePriority( &moduleList[ i ] );

		if ( moduleList[ i ].modBaseAddr + moduleList[ i ].modBaseSize > maxValidAddress )
		{
			maxValidAddress = moduleList[ i ].modBaseAddr + moduleList[ i ].modBaseSize;
		}


		LOGS( "Module parsing: %s", moduleList[ i ].fullPath );

		if ( !moduleList[ i ].isAlreadyParsed )
		{
			parseModule( &moduleList[ i ] );
		}
	}


	LOGS_DEBUG( "Address Min " PRINTF_DWORD_PTR_FULL_S " Max " PRINTF_DWORD_PTR_FULL_S "\nimagebase " PRINTF_DWORD_PTR_FULL_S " maxValidAddress " PRINTF_DWORD_PTR_FULL_S, minApiAddress, maxApiAddress, targetImageBase, maxValidAddress );

}

void ApiReader::parseModule( ModuleInfo* module )
{
	module->parsing = true;

	if ( isWinSxSModule( module ) )
	{
		parseModuleWithMapping( module );
	}
	else if ( isModuleLoadedInOwnProcess( module ) ) //this is always ok
	{
		parseModuleWithOwnProcess( module );
	}
	else
	{
		if ( readExportTableAlwaysFromDisk )
		{
			parseModuleWithMapping( module );
		}
		else
		{
			parseModuleWithProcess( module );
		}
	}

	module->isAlreadyParsed = true;
}

void ApiReader::parseModuleWithMapping( ModuleInfo* moduleInfo )
{
	LPVOID fileMapping = 0;
	PIMAGE_NT_HEADERS pNtHeader = 0;
	PIMAGE_DOS_HEADER pDosHeader = 0;

	fileMapping = createFileMappingViewRead( moduleInfo->fullPath );

	if ( fileMapping == 0 )
		return;

	pDosHeader = (PIMAGE_DOS_HEADER)fileMapping;
	pNtHeader = (PIMAGE_NT_HEADERS)( (DWORD_PTR)fileMapping + (DWORD_PTR)( pDosHeader->e_lfanew ) );

	if ( isPeAndExportTableValid( pNtHeader ) )
	{
		parseExportTable( moduleInfo, pNtHeader, (PIMAGE_EXPORT_DIRECTORY)( (DWORD_PTR)fileMapping + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress ), (DWORD_PTR)fileMapping );
	}


	UnmapViewOfFile( fileMapping );

}

inline bool ApiReader::isApiForwarded( DWORD_PTR rva, PIMAGE_NT_HEADERS pNtHeader )
{
	if ( ( rva > pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress ) && ( rva < ( pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size ) ) )
	{
		return true;
	}
	else
	{
		return false;
	}
}

void ApiReader::handleForwardedApi( DWORD_PTR vaStringPointer, char* functionNameParent, DWORD_PTR rvaParent, WORD ordinalParent, ModuleInfo* moduleParent )
{
	size_t dllNameLength = 0;
	WORD ordinal = 0;
	ModuleInfo* module = 0;
	DWORD_PTR vaApi = 0;
	DWORD_PTR rvaApi = 0;
	char dllName[ 100 ] = { 0 };
	WCHAR dllNameW[ 100 ] = { 0 };
	char* fordwardedString = (char*)vaStringPointer;
	char* searchFunctionName = strchr( fordwardedString, '.' );


	if ( !searchFunctionName )
		return;

	dllNameLength = searchFunctionName - fordwardedString;

	if ( dllNameLength >= 99 )
	{
		return;
	}
	else
	{
		strncpy_s( dllName, fordwardedString, dllNameLength );
	}

	searchFunctionName++;

	if ( strchr( searchFunctionName, '#' ) )
	{
		searchFunctionName++;
		ordinal = (WORD)atoi( searchFunctionName );
	}

	//Since Windows 7
	if ( !_strnicmp( dllName, "API-", 4 ) || !_strnicmp( dllName, "EXT-", 4 ) ) //API_SET_PREFIX_NAME, API_SET_EXTENSION
	{
		/*
				Info: http://www.nirsoft.net/articles/windows_7_kernel_architecture_changes.html
		*/
		FARPROC addy = 0;
		HMODULE hModTemp = GetModuleHandleA( dllName );
		if ( hModTemp == 0 )
		{
			hModTemp = LoadLibraryA( dllName );
		}

		if ( ordinal )
		{
			addy = GetProcAddress( hModTemp, (char*)ordinal );
		}
		else
		{
			addy = GetProcAddress( hModTemp, searchFunctionName );
		}

		LOGS_DEBUG( "API_SET_PREFIX_NAME %s %S Module Handle %p addy %p", moduleParent->fullPath, dllName, hModTemp, addy );

		if ( addy != 0 )
		{
			addApi( functionNameParent, 0, ordinalParent, (DWORD_PTR)addy, (DWORD_PTR)addy - (DWORD_PTR)hModTemp, true, moduleParent );
		}

		return;
	}

	strcat_s( dllName, ".dll" );

	StringConversion::ToUTF16( dllName, dllNameW, _countof( dllNameW ) );

	if ( !_wcsicmp( dllNameW, moduleParent->getFilename( ) ) )
	{
		module = moduleParent;
	}
	else
	{
		module = findModuleByName( dllNameW );
	}

	if ( module != 0 ) // module == 0 -> can be ignored
	{
		/*if ((module->isAlreadyParsed == false) && (module != moduleParent))
		{
			//do API extract

			if (module->parsing == true)
			{
				//some stupid circle dependency
				printf("stupid circle dependency %s\n",module->getFilename());
			}
			else
			{
				parseModule(module);
			}
		}*/

		if ( ordinal )
		{
			//forwarding by ordinal
			findApiByModuleAndOrdinal( module, ordinal, &vaApi, &rvaApi );
		}
		else
		{
			findApiByModuleAndName( module, searchFunctionName, &vaApi, &rvaApi );
		}

		if ( rvaApi == 0 )
		{

			LOGS_DEBUG( "handleForwardedApi :: Api not found, this is really BAD! %S", fordwardedString );

		}
		else
		{
			addApi( functionNameParent, 0, ordinalParent, vaApi, rvaApi, true, moduleParent );
		}
	}

}

ModuleInfo* ApiReader::findModuleByName( WCHAR* name )
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
	BYTE* bufferHeader = 0;
	DWORD readSize = 0;

	if ( module->modBaseSize < PE_HEADER_BYTES_COUNT )
	{
		readSize = module->modBaseSize;
	}
	else
	{
		readSize = PE_HEADER_BYTES_COUNT;
	}

	bufferHeader = new BYTE[ readSize ];

	if ( !readMemoryFromProcess( module->modBaseAddr, readSize, bufferHeader ) )
	{

		LOGS_DEBUG( "getHeaderFromProcess :: Error reading header" );

		delete[ ] bufferHeader;
		return 0;
	}
	else
	{
		return bufferHeader;
	}
}

BYTE* ApiReader::getExportTableFromProcess( ModuleInfo* module, PIMAGE_NT_HEADERS pNtHeader )
{
	DWORD readSize = 0;
	BYTE* bufferExportTable = 0;

	readSize = pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

	if ( readSize < ( sizeof( IMAGE_EXPORT_DIRECTORY ) + 8 ) )
	{
		//Something is wrong with the PE Header

		LOGS_DEBUG( "Something is wrong with the PE Header here Export table size %d", readSize );

		readSize = sizeof( IMAGE_EXPORT_DIRECTORY ) + 100;
	}

	if ( readSize )
	{
		bufferExportTable = new BYTE[ readSize ];

		if ( !bufferExportTable )
		{

			LOGS_DEBUG( "Something is wrong with the PE Header here Export table size %d", readSize );

			return 0;
		}

		if ( !readMemoryFromProcess( module->modBaseAddr + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, readSize, bufferExportTable ) )
		{

			LOGS_DEBUG( "getExportTableFromProcess :: Error reading export table from process" );

			delete[ ] bufferExportTable;
			return 0;
		}
		else
		{
			return bufferExportTable;
		}
	}
	else
	{
		return 0;
	}
}

void ApiReader::parseModuleWithProcess( ModuleInfo* module )
{
	PIMAGE_NT_HEADERS pNtHeader = 0;
	PIMAGE_DOS_HEADER pDosHeader = 0;
	BYTE* bufferHeader = 0;
	BYTE* bufferExportTable = 0;
	PeParser peParser( module->modBaseAddr, false );

	if ( !peParser.isValidPeFile( ) )
		return;

	pNtHeader = peParser.getCurrentNtHeader( );

	if ( peParser.hasExportDirectory( ) )
	{
		bufferExportTable = getExportTableFromProcess( module, pNtHeader );

		if ( bufferExportTable )
		{
			parseExportTable( module, pNtHeader, (PIMAGE_EXPORT_DIRECTORY)bufferExportTable, (DWORD_PTR)bufferExportTable - pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
			delete[ ] bufferExportTable;
		}
	}
}

void ApiReader::parseExportTable( ModuleInfo* module, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress )
{
	DWORD* addressOfFunctionsArray = 0, * addressOfNamesArray = 0;
	WORD* addressOfNameOrdinalsArray = 0;
	char* functionName = 0;
	DWORD_PTR RVA = 0, VA = 0;
	WORD ordinal = 0;
	WORD i = 0, j = 0;
	bool withoutName;


	addressOfFunctionsArray = (DWORD*)( (DWORD_PTR)pExportDir->AddressOfFunctions + deltaAddress );
	addressOfNamesArray = (DWORD*)( (DWORD_PTR)pExportDir->AddressOfNames + deltaAddress );
	addressOfNameOrdinalsArray = (WORD*)( (DWORD_PTR)pExportDir->AddressOfNameOrdinals + deltaAddress );


	LOGS_DEBUG( "parseExportTable :: module %s NumberOfNames %X", module->fullPath, pExportDir->NumberOfNames );


	for ( i = 0; i < pExportDir->NumberOfNames; i++ )
	{
		functionName = (char*)( addressOfNamesArray[ i ] + deltaAddress );
		ordinal = (WORD)( addressOfNameOrdinalsArray[ i ] + pExportDir->Base );
		RVA = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ];
		VA = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ] + module->modBaseAddr;


		LOGS_DEBUG( "parseExportTable :: api %S ordinal %d imagebase " PRINTF_DWORD_PTR_FULL_S " RVA " PRINTF_DWORD_PTR_FULL_S " VA " PRINTF_DWORD_PTR_FULL_S, functionName, ordinal, module->modBaseAddr, RVA, VA );

		if ( !isApiBlacklisted( functionName ) )
		{
			if ( !isApiForwarded( RVA, pNtHeader ) )
			{
				addApi( functionName, i, ordinal, VA, RVA, false, module );
			}
			else
			{
				//printf("Forwarded: %s\n",functionName);
				handleForwardedApi( RVA + deltaAddress, functionName, RVA, ordinal, module );
			}
		}

	}

	/*Exports without name*/
	if ( pExportDir->NumberOfNames != pExportDir->NumberOfFunctions )
	{
		for ( i = 0; i < pExportDir->NumberOfFunctions; i++ )
		{
			withoutName = true;
			for ( j = 0; j < pExportDir->NumberOfNames; j++ )
			{
				if ( addressOfNameOrdinalsArray[ j ] == i )
				{
					withoutName = false;
					break;
				}
			}
			if ( withoutName && addressOfFunctionsArray[ i ] != 0 )
			{
				ordinal = (WORD)( i + pExportDir->Base );
				RVA = addressOfFunctionsArray[ i ];
				VA = ( addressOfFunctionsArray[ i ] + module->modBaseAddr );


				if ( !isApiForwarded( RVA, pNtHeader ) )
				{
					addApiWithoutName( ordinal, VA, RVA, false, module );
				}
				else
				{
					handleForwardedApi( RVA + deltaAddress, 0, RVA, ordinal, module );
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

void ApiReader::findApiByModule( ModuleInfo* module, char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	if ( isModuleLoadedInOwnProcess( module ) )
	{
		HMODULE hModule = GetModuleHandle( module->getFilename( ) );

		if ( hModule )
		{
			if ( vaApi )
			{
				if ( ordinal )
				{
					*vaApi = (DWORD_PTR)GetProcAddress( hModule, (LPCSTR)ordinal );
				}
				else
				{
					*vaApi = (DWORD_PTR)GetProcAddress( hModule, searchFunctionName );
				}

				*rvaApi = ( *vaApi ) - (DWORD_PTR)hModule;
				*vaApi = ( *rvaApi ) + module->modBaseAddr;
			}
			else
			{

				LOGS_DEBUG( "findApiByModule :: vaApi == NULL, should never happen %S", searchFunctionName );

			}
		}
		else
		{

			LOGS_DEBUG( "findApiByModule :: hModule == NULL, should never happen %s", module->getFilename( ) );

		}
	}
	else
	{
		//search api in extern process
		findApiInProcess( module, searchFunctionName, ordinal, vaApi, rvaApi );
	}
}

bool ApiReader::isModuleLoadedInOwnProcess( ModuleInfo* module )
{
	for ( unsigned int i = 0; i < ownModuleList.size( ); i++ )
	{
		if ( !_wcsicmp( module->fullPath, ownModuleList[ i ].fullPath ) )
		{
			//printf("isModuleLoadedInOwnProcess :: %s %s\n",module->fullPath,ownModuleList[i].fullPath);
			return true;
		}
	}
	return false;
}

void ApiReader::parseModuleWithOwnProcess( ModuleInfo* module )
{
	PIMAGE_NT_HEADERS pNtHeader = 0;
	PIMAGE_DOS_HEADER pDosHeader = 0;
	HMODULE hModule = GetModuleHandle( module->getFilename( ) );

	if ( hModule )
	{
		pDosHeader = (PIMAGE_DOS_HEADER)hModule;
		pNtHeader = (PIMAGE_NT_HEADERS)( (DWORD_PTR)hModule + (DWORD_PTR)( pDosHeader->e_lfanew ) );

		if ( isPeAndExportTableValid( pNtHeader ) )
		{
			parseExportTable( module, pNtHeader, (PIMAGE_EXPORT_DIRECTORY)( (DWORD_PTR)hModule + pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress ), (DWORD_PTR)hModule );
		}
	}
	else
	{

		LOGS_DEBUG( "parseModuleWithOwnProcess :: hModule is NULL" );

	}
}

bool ApiReader::isPeAndExportTableValid( PIMAGE_NT_HEADERS pNtHeader )
{
	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE )
	{

		LOGS( "-> IMAGE_NT_SIGNATURE doesn't match." );

		return false;
	}
	else if ( ( pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress == 0 ) || ( pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size == 0 ) )
	{

		LOGS( "-> No export table." );

		return false;
	}
	else
	{
		return true;
	}
}

void ApiReader::findApiInProcess( ModuleInfo* module, char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	PIMAGE_NT_HEADERS pNtHeader = 0;
	PIMAGE_DOS_HEADER pDosHeader = 0;
	BYTE* bufferHeader = 0;
	BYTE* bufferExportTable = 0;


	bufferHeader = getHeaderFromProcess( module );

	if ( bufferHeader == 0 )
		return;

	pDosHeader = (PIMAGE_DOS_HEADER)bufferHeader;
	pNtHeader = (PIMAGE_NT_HEADERS)( (DWORD_PTR)bufferHeader + (DWORD_PTR)( pDosHeader->e_lfanew ) );

	if ( isPeAndExportTableValid( pNtHeader ) )
	{
		bufferExportTable = getExportTableFromProcess( module, pNtHeader );

		if ( bufferExportTable )
		{
			findApiInExportTable( module, (PIMAGE_EXPORT_DIRECTORY)bufferExportTable, (DWORD_PTR)bufferExportTable - pNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, searchFunctionName, ordinal, vaApi, rvaApi );
			delete[ ] bufferExportTable;
		}
	}

	delete[ ] bufferHeader;
}

bool ApiReader::findApiInExportTable( ModuleInfo* module, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress, char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi )
{
	DWORD* addressOfFunctionsArray = 0, * addressOfNamesArray = 0;
	WORD* addressOfNameOrdinalsArray = 0;
	char* functionName = 0;
	DWORD i = 0, j = 0;

	addressOfFunctionsArray = (DWORD*)( (DWORD_PTR)pExportDir->AddressOfFunctions + deltaAddress );
	addressOfNamesArray = (DWORD*)( (DWORD_PTR)pExportDir->AddressOfNames + deltaAddress );
	addressOfNameOrdinalsArray = (WORD*)( (DWORD_PTR)pExportDir->AddressOfNameOrdinals + deltaAddress );

	if ( searchFunctionName )
	{
		for ( i = 0; i < pExportDir->NumberOfNames; i++ )
		{
			functionName = (char*)( addressOfNamesArray[ i ] + deltaAddress );

			if ( !strcmp( functionName, searchFunctionName ) )
			{
				*rvaApi = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ];
				*vaApi = addressOfFunctionsArray[ addressOfNameOrdinalsArray[ i ] ] + module->modBaseAddr;
				return true;
			}
		}
	}
	else
	{
		for ( i = 0; i < pExportDir->NumberOfFunctions; i++ )
		{
			if ( ordinal == ( i + pExportDir->Base ) )
			{
				*rvaApi = addressOfFunctionsArray[ i ];
				*vaApi = ( addressOfFunctionsArray[ i ] + module->modBaseAddr );
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

ApiInfo* ApiReader::getApiByVirtualAddress( DWORD_PTR virtualAddress, bool* isSuspect )
{
	stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator it1, it2;
	size_t c = 0;
	size_t countDuplicates = apiList.count( virtualAddress );
	int countHighPriority = 0;
	ApiInfo* apiFound = 0;


	if ( countDuplicates == 0 )
	{
		return 0;
	}
	else if ( countDuplicates == 1 )
	{
		//API is 100% correct
		*isSuspect = false;
		it1 = apiList.find( virtualAddress ); // Find first match.
		return (ApiInfo*)( ( *it1 ).second );
	}
	else
	{
		it1 = apiList.find( virtualAddress ); // Find first match.

		//any high priority with a name
		apiFound = getScoredApi( it1, countDuplicates, true, false, false, true, false, false, false, false );

		if ( apiFound )
			return apiFound;

		*isSuspect = true;

		//high priority with a name and ansi/unicode name
		apiFound = getScoredApi( it1, countDuplicates, true, true, false, true, false, false, false, false );

		if ( apiFound )
			return apiFound;

		//priority 2 with no underline in name
		apiFound = getScoredApi( it1, countDuplicates, true, false, true, false, false, false, true, false );

		if ( apiFound )
			return apiFound;

		//priority 1 with a name
		apiFound = getScoredApi( it1, countDuplicates, true, false, false, false, false, true, false, false );

		if ( apiFound )
			return apiFound;

		//With a name
		apiFound = getScoredApi( it1, countDuplicates, true, false, false, false, false, false, false, false );

		if ( apiFound )
			return apiFound;

		//any with priority, name, ansi/unicode
		apiFound = getScoredApi( it1, countDuplicates, true, true, false, true, false, false, false, true );

		if ( apiFound )
			return apiFound;

		//any with priority
		apiFound = getScoredApi( it1, countDuplicates, false, false, false, true, false, false, false, true );

		if ( apiFound )
			return apiFound;

		//has prio 0 and name
		apiFound = getScoredApi( it1, countDuplicates, false, false, false, false, true, false, false, true );

		if ( apiFound )
			return apiFound;
	}


	//is never reached
	LOGS( "getApiByVirtualAddress :: There is a api resolving bug, VA: " PRINTF_DWORD_PTR_FULL_S, virtualAddress );


	for ( size_t c = 0; c < countDuplicates; c++, it1++ )
	{
		apiFound = (ApiInfo*)( ( *it1 ).second );


		LOGS( "-> Possible API: %S ord: %d ", apiFound->name, apiFound->ordinal );

	}
	return (ApiInfo*)1;
}

ApiInfo* ApiReader::getScoredApi( stdext::hash_multimap<DWORD_PTR, ApiInfo*>::iterator it1, size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll, bool hasPrio0Dll, bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin )
{
	ApiInfo* foundApi = 0;
	ApiInfo* foundMatchingApi = 0;
	int countFoundApis = 0;
	int scoreNeeded = 0;
	int scoreValue = 0;
	size_t apiNameLength = 0;

	if ( hasUnicodeAnsiName || hasNoUnderlineInName )
	{
		hasName = true;
	}

	if ( hasName )
		scoreNeeded++;

	if ( hasUnicodeAnsiName )
		scoreNeeded++;

	if ( hasNoUnderlineInName )
		scoreNeeded++;

	if ( hasPrioDll )
		scoreNeeded++;

	if ( hasPrio0Dll )
		scoreNeeded++;

	if ( hasPrio1Dll )
		scoreNeeded++;

	if ( hasPrio2Dll )
		scoreNeeded++;

	for ( size_t c = 0; c < countDuplicates; c++, it1++ )
	{
		foundApi = (ApiInfo*)( ( *it1 ).second );
		scoreValue = 0;

		if ( hasName )
		{
			if ( foundApi->name[ 0 ] != 0x00 )
			{
				scoreValue++;

				if ( hasUnicodeAnsiName )
				{
					apiNameLength = strlen( foundApi->name );

					if ( ( foundApi->name[ apiNameLength - 1 ] == 'W' ) || ( foundApi->name[ apiNameLength - 1 ] == 'A' ) )
					{
						scoreValue++;
					}
				}

				if ( hasNoUnderlineInName )
				{
					if ( !strrchr( foundApi->name, '_' ) )
					{
						scoreValue++;
					}
				}
			}
		}

		if ( hasPrioDll )
		{
			if ( foundApi->module->priority >= 1 )
			{
				scoreValue++;
			}
		}

		if ( hasPrio0Dll )
		{
			if ( foundApi->module->priority == 0 )
			{
				scoreValue++;
			}
		}

		if ( hasPrio1Dll )
		{
			if ( foundApi->module->priority == 1 )
			{
				scoreValue++;
			}
		}

		if ( hasPrio2Dll )
		{
			if ( foundApi->module->priority == 2 )
			{
				scoreValue++;
			}
		}


		if ( scoreValue == scoreNeeded )
		{
			foundMatchingApi = foundApi;
			countFoundApis++;

			if ( firstWin )
			{
				return foundMatchingApi;
			}
		}
	}

	if ( countFoundApis == 1 )
	{
		return foundMatchingApi;
	}
	else
	{
		return (ApiInfo*)0;
	}

}

void ApiReader::setMinMaxApiAddress( DWORD_PTR virtualAddress )
{
	if ( virtualAddress == 0 || virtualAddress == (DWORD_PTR)-1 )
		return;

	if ( virtualAddress < minApiAddress )
	{

		LOGS_DEBUG( "virtualAddress %p < minApiAddress %p", virtualAddress, minApiAddress );

		minApiAddress = virtualAddress - 1;
	}
	if ( virtualAddress > maxApiAddress )
	{
		maxApiAddress = virtualAddress + 1;
	}
}

void  ApiReader::readAndParseIAT( DWORD_PTR addressIAT, DWORD sizeIAT, std::map<DWORD_PTR, ImportModuleThunk>& moduleListNew )
{
	moduleThunkList = &moduleListNew;
	BYTE* dataIat = new BYTE[ sizeIAT ];
	if ( readMemoryFromProcess( addressIAT, sizeIAT, dataIat ) )
	{
		parseIAT( addressIAT, dataIat, sizeIAT );
	}
	else
	{

		LOGS_DEBUG( "ApiReader::readAndParseIAT :: error reading iat " PRINTF_DWORD_PTR_FULL_S, addressIAT );

	}

	delete[ ] dataIat;
}

void ApiReader::parseIAT( DWORD_PTR addressIAT, BYTE* iatBuffer, SIZE_T size )
{
	ApiInfo* apiFound = 0;
	ModuleInfo* module = 0;
	bool isSuspect = false;
	int countApiFound = 0, countApiNotFound = 0;
	DWORD_PTR* pIATAddress = (DWORD_PTR*)iatBuffer;
	SIZE_T sizeIAT = size / sizeof( DWORD_PTR );

	for ( SIZE_T i = 0; i < sizeIAT; i++ )
	{
		//LOGS( "%08X %08X %d von %d", addressIAT + (DWORD_PTR)&pIATAddress[i] - (DWORD_PTR)iatBuffer, pIATAddress[i],i,sizeIAT);

		if ( !isInvalidMemoryForIat( pIATAddress[ i ] ) )
		{

			LOGS_DEBUG( "min %p max %p address %p", minApiAddress, maxApiAddress, pIATAddress[ i ] );

			if ( ( pIATAddress[ i ] > minApiAddress ) && ( pIATAddress[ i ] < maxApiAddress ) )
			{

				apiFound = getApiByVirtualAddress( pIATAddress[ i ], &isSuspect );


				LOGS_DEBUG( "apiFound %p address %p", apiFound, pIATAddress[ i ] );

				if ( apiFound == 0 )
				{

					LOGS( "getApiByVirtualAddress :: No Api found " PRINTF_DWORD_PTR_FULL_S, pIATAddress[ i ] );

				}
				if ( apiFound == (ApiInfo*)1 )
				{

					LOGS_DEBUG( "apiFound == (ApiInfo *)1 -> " PRINTF_DWORD_PTR_FULL_S, pIATAddress[ i ] );

				}
				else if ( apiFound )
				{
					countApiFound++;

					LOGS_DEBUG( PRINTF_DWORD_PTR_FULL_S " %s %d %s", apiFound->va, apiFound->module->getFilename( ), apiFound->ordinal, apiFound->name );

					if ( module != apiFound->module )
					{
						module = apiFound->module;
						addFoundApiToModuleList( addressIAT + (DWORD_PTR)&pIATAddress[ i ] - (DWORD_PTR)iatBuffer, apiFound, true, isSuspect );
					}
					else
					{
						addFoundApiToModuleList( addressIAT + (DWORD_PTR)&pIATAddress[ i ] - (DWORD_PTR)iatBuffer, apiFound, false, isSuspect );
					}

				}
				else
				{
					countApiNotFound++;
					addNotFoundApiToModuleList( addressIAT + (DWORD_PTR)&pIATAddress[ i ] - (DWORD_PTR)iatBuffer, pIATAddress[ i ] );
					//printf("parseIAT :: API not found %08X\n", pIATAddress[i]);
				}
			}
			else
			{
				//printf("parseIAT :: API not found %08X\n", pIATAddress[i]);
				countApiNotFound++;
				addNotFoundApiToModuleList( addressIAT + (DWORD_PTR)&pIATAddress[ i ] - (DWORD_PTR)iatBuffer, pIATAddress[ i ] );
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