#pragma once
#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#include <windows.h>
#include <map>
#include <hash_map>
#include <memory>
#include "ProcessAccessHelp.h"
#include "Thunks.h"
#include <unordered_map>

typedef std::pair<DWORD_PTR, ApiInfo*> API_Pair;

class ApiReader : public ProcessAccessHelp
{
public:
	static stdext::hash_multimap<DWORD_PTR, ApiInfo*> apiList; //api look up table

	static std::map<DWORD_PTR, ImportModuleThunk>* moduleThunkList; //store found apis

	static DWORD_PTR minApiAddress;
	static DWORD_PTR maxApiAddress;

	/*
	 * Read all APIs from target process
	 */
	void readApisFromModuleList( );

	bool isApiAddressValid( DWORD_PTR virtualAddress );
	ApiInfo* getApiByVirtualAddress( DWORD_PTR virtualAddress, bool* isSuspect );
	void readAndParseIAT( DWORD_PTR addressIAT, DWORD sizeIAT, std::map<DWORD_PTR, ImportModuleThunk>& moduleListNew );
	void addFoundApiToModuleList( DWORD_PTR iatAddress, ApiInfo* apiFound, bool isNewModule, bool isSuspect );
	void clearAll( );
	bool isInvalidMemoryForIat( DWORD_PTR address );
private:

	ImportModuleThunk* findModuleForRVA( DWORD_PTR rva, bool addUnknownModuleIfNeeded = false );
	bool readExportTableAlwaysFromDisk;
	void parseIAT( DWORD_PTR addressIAT, BYTE* iatBuffer, SIZE_T size );

	void addApi( const char* functionName, WORD hint, WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo* moduleInfo );
	void addApiWithoutName( WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo* moduleInfo );
	inline bool isApiForwarded( DWORD_PTR rva, PIMAGE_NT_HEADERS pNtHeader );
	void handleForwardedApi( DWORD_PTR vaStringPointer, const char* functionNameParent, DWORD_PTR rvaParent, WORD ordinalParent, ModuleInfo* moduleParent );
	void parseModule( ModuleInfo* pModule );
	void parseModuleWithProcess( ModuleInfo* pModule );

	void parseExportTable( ModuleInfo* pModule, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress );

	ModuleInfo* findModuleByName( const WCHAR* name );

	void findApiByModuleAndOrdinal( ModuleInfo* pModule, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi );
	void findApiByModuleAndName( ModuleInfo* pModule, const char* searchFunctionName, DWORD_PTR* vaApi, DWORD_PTR* rvaApi );
	void findApiByModule( ModuleInfo* pModule, const char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi );

	bool isModuleLoadedInOwnProcess( ModuleInfo* pModule );
	void parseModuleWithOwnProcess( ModuleInfo* pModule );
	bool isPeAndExportTableValid( PIMAGE_NT_HEADERS pNtHeader );
	void findApiInProcess( ModuleInfo* pModule, const char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi );
	bool findApiInExportTable( ModuleInfo* pModule, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress, const char* searchFunctionName, WORD ordinal, DWORD_PTR* vaApi, DWORD_PTR* rvaApi );

	std::unique_ptr<BYTE[ ]> getHeaderFromProcess( ModuleInfo* pModule );
	std::unique_ptr<BYTE[ ]> getExportTableFromProcess( ModuleInfo* pModule, PIMAGE_NT_HEADERS pNtHeader );

	void setModulePriority( ModuleInfo* pModule );
	void setMinMaxApiAddress( DWORD_PTR virtualAddress );

	void parseModuleWithMapping( ModuleInfo* moduleInfo ); //not used

	bool addModuleToModuleList( const WCHAR* moduleName, DWORD_PTR firstThunk );
	bool addFunctionToModuleList( ApiInfo* apiFound, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect );
	bool addNotFoundApiToModuleList( DWORD_PTR iatAddressVA, DWORD_PTR apiAddress );

	void addUnknownModuleToModuleList( DWORD_PTR firstThunk );
	bool isApiBlacklisted( const char* functionName );
	bool isWinSxSModule( ModuleInfo* pModule );

	ApiInfo* getScoredApi( stdext::hash_map<DWORD_PTR, ApiInfo*>::iterator it1, size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll, bool hasPrio0Dll, bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin );

};