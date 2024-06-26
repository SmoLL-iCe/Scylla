#pragma once
#include <windows.h>
#include <map>
#include <hash_map>
#include <memory>
#include "ProcessAccessHelp.h"
#include "Thunks.h"
#include <unordered_map>

typedef std::pair<std::uintptr_t, ApiInfo*> API_Pair;

class ApiReader : public ProcessAccessHelp
{
public:
	static stdext::hash_multimap<std::uintptr_t, ApiInfo*> mpApiList; //api look up table

	static std::map<std::uintptr_t, ImportModuleThunk>* mpModuleThunkList; //store found apis

	static std::uintptr_t uMinApiAddress;
	static std::uintptr_t uMaxApiAddress;

	/*
	 * Read all APIs from target process
	 */
	void readApisFromModuleList( );

	bool isApiAddressValid( std::uintptr_t uVirtualAddress );
	ApiInfo* getApiByVirtualAddress( std::uintptr_t uVirtualAddress, bool* pIsSuspect );
	void readAndParseIAT( std::uintptr_t uAddressIAT, std::uint32_t uSizeIAT, std::map<std::uintptr_t, ImportModuleThunk>& mpModuleListNew );
	void addFoundApiToModuleList( std::uintptr_t uIATAddress, ApiInfo* pApiFound, bool isNewModule, bool isSuspect );
	void clearAll( );
	bool isInvalidMemoryForIat( std::uintptr_t uAddress );
private:

	ImportModuleThunk* findModuleForRVA( std::uintptr_t RVA, bool addUnknownModuleIfNeeded = false );
	bool readExportTableAlwaysFromDisk;
	void parseIAT( std::uintptr_t uAddressIAT, std::uint8_t* pIatBuffer, std::size_t szSize );

	void addApi( const char* pFuncName, std::uint16_t uHint, std::uint16_t uOrdinal, std::uintptr_t VA, std::uintptr_t RVA, bool isForwarded, ModuleInfo* pModuleInfo );
	void addApiWithoutName( std::uint16_t uOrdinal, std::uintptr_t VA, std::uintptr_t RVA, bool isForwarded, ModuleInfo* pModuleInfo );
	static bool isApiForwarded( std::uintptr_t RVA, PIMAGE_NT_HEADERS pNtHeader );
	void handleForwardedApi( std::uintptr_t uVaStringPointer, const char* pFuncNameParent, std::uintptr_t uRvaParent, std::uint16_t uOrdinalParent, ModuleInfo* pModuleParent );
	void parseModule( ModuleInfo* pModule );
	void parseModuleWithProcess( ModuleInfo* pModule );

	void parseExportTable( ModuleInfo* pModule, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, std::uintptr_t uDeltaAddress );

	ModuleInfo* findModuleByName( const wchar_t* pName );

	void findApiByModuleAndOrdinal( ModuleInfo* pModule, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi );
	void findApiByModuleAndName( ModuleInfo* pModule, const char* pSearchFunctionName, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi );
	void findApiByModule( ModuleInfo* pModule, const char* pSearchFunctionName, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi );

	bool isModuleLoadedInOwnProcess( ModuleInfo* pModule );
	void parseModuleWithOwnProcess( ModuleInfo* pModule );
	bool isPeAndExportTableValid( PIMAGE_NT_HEADERS pNtHeader );
	void findApiInProcess( ModuleInfo* pModule, const char* pSearchFunctionName, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi );
	bool findApiInExportTable( ModuleInfo* pModule, PIMAGE_EXPORT_DIRECTORY pExportDir, std::uintptr_t uDeltaAddress, const char* pSearchFunctionName, std::uint16_t uOrdinal, std::uintptr_t* pVaApi, std::uintptr_t* pRvaApi );

	std::unique_ptr<std::uint8_t[ ]> getHeaderFromProcess( ModuleInfo* pModule );
	std::unique_ptr<std::uint8_t[ ]> getExportTableFromProcess( ModuleInfo* pModule, PIMAGE_NT_HEADERS pNtHeader );

	void setModulePriority( ModuleInfo* pModule );
	void setMinMaxApiAddress( std::uintptr_t uVirtualAddress );

	void parseModuleWithMapping( ModuleInfo* pModuleInfo ); //not used

	bool addModuleToModuleList( const wchar_t* pModuleName, std::uintptr_t uFirstThunk );
	bool addFunctionToModuleList( ApiInfo* pApiFound, std::uintptr_t VA, std::uintptr_t RVA, std::uint16_t uOrdinal, bool valid, bool suspect );
	bool addNotFoundApiToModuleList( std::uintptr_t uIatAddressVA, std::uintptr_t uApiAddress );

	void addUnknownModuleToModuleList( std::uintptr_t uFirstThunk );
	bool isApiBlacklisted( const char* pFuncName );
	bool isWinSxSModule( ModuleInfo* pModule );

	ApiInfo* getScoredApi( stdext::hash_map<std::uintptr_t, ApiInfo*>::iterator it1, std::size_t szCountDuplicates,
		bool bHasName, bool bHasUnicodeAnsiName,
		bool bHasNoUnderlineInName, bool bHasPrioDll, bool bHasPrio0Dll, bool bHasPrio1Dll, bool bHasPrio2Dll, bool bFirstWin );

};