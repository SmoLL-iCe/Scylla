#include "ImportsHandling.h"
#include "Thunks.h"
#include "Architecture.h"
#include "Tools/Logs.h"
#include <algorithm>

void ImportThunk::invalidate( )
{
	ordinal = 0;
	hint = 0;
	valid = false;
	suspect = false;
	moduleName[ 0 ] = 0;
	name[ 0 ] = 0;
}

bool ImportModuleThunk::isValid( ) const
{
	return std::all_of( thunkList.begin( ), thunkList.end( ), [ ]( const auto& pair ) {
		return pair.second.valid;
		} );
}

DWORD_PTR ImportModuleThunk::getFirstThunk( ) const
{
	if ( !thunkList.empty( ) )
	{
		return thunkList.begin( )->first;
	}
	return 0;
}

ImportsHandling::ImportsHandling( )
{
	m_thunkCount = m_invalidThunkCount = m_suspectThunkCount = 0;
}

ImportsHandling::~ImportsHandling( ) {}

ImportModuleThunk* ImportsHandling::getModuleThunk( ImportThunk* pImport )
{
	for ( auto& [key, moduleThunk] : moduleList )
	{
		for ( auto& [key, importThunk] : moduleThunk.thunkList )
		{
			if ( importThunk.key == pImport->key )
			{
				return &moduleThunk;
			}
		}
	}

	return nullptr;
}

void ImportsHandling::updateCounts( )
{
	m_thunkCount = m_invalidThunkCount = m_suspectThunkCount = 0;

	for ( const auto& [key, moduleThunk] : moduleList )
	{
		for ( const auto& [thunkKey, importThunk] : moduleThunk.thunkList )
		{
			m_thunkCount++;
			if ( !importThunk.valid )
				m_invalidThunkCount++;
			else if ( importThunk.suspect )
				m_suspectThunkCount++;
		}
	}
}

/*
bool ImportsHandling::addImport(const WCHAR * moduleName, const CHAR * name, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect)
{
	ImportModuleThunk* pModule = nullptr;

	if (!moduleList.empty())
	{
		auto it = std::find_if(moduleList.begin(), moduleList.end(), [rva](const std::pair<DWORD_PTR, ImportModuleThunk>& modulePair) {
			return rva >= modulePair.second.firstThunk && (modulePair.first == moduleList.rbegin()->first || rva < std::next(&modulePair)->second.firstThunk);
		});

		if (it != moduleList.end())
		{
			pModule = &(it->second);
		}
	}

	if (!pModule)
	{
		Scylla::debugLog.log(L"ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL, rva);
		return false;
	}

	ImportThunk pImport;
	pImport.suspect = suspect;
	pImport.valid = valid;
	pImport.va = va;
	pImport.rva = rva;
	pImport.ordinal = ordinal;

	wcscpy_s(pImport.moduleName, MAX_PATH, moduleName);
	strcpy_s(pImport.name, MAX_PATH, name);

	pModule->thunkList.insert(std::make_pair(pImport.rva, pImport));

	return true;
}

*/

/*
bool ImportsHandling::addModule(const WCHAR * moduleName, DWORD_PTR firstThunk)
{
	ImportModuleThunk pModule;

	pModule.firstThunk = firstThunk;
	wcscpy_s(pModule.moduleName, MAX_PATH, moduleName);

	moduleList.insert(std::pair<DWORD_PTR,ImportModuleThunk>(firstThunk,pModule));

	return true;
}
*/

void ImportsHandling::displayAllImports( )
{
	for ( auto& [key, moduleThunk] : moduleList )
	{
		moduleThunk.key = moduleThunk.firstThunk; // This belongs elsewhere...
		//moduleThunk.hTreeItem = addDllToTreeView(TreeImports, &moduleThunk);

		for ( auto& [thunkKey, importThunk] : moduleThunk.thunkList )
		{
			importThunk.key = importThunk.rva; // This belongs elsewhere...
			//importThunk.hTreeItem = addApiToTreeView(TreeImports, moduleThunk.hTreeItem, &importThunk);
		}
	}

	updateCounts( );
}

void ImportsHandling::clearAllImports( )
{
	moduleList.clear( );
	updateCounts( );
}

bool ImportsHandling::invalidateImport( ImportThunk* pImport )
{
	if ( pImport )
	{
		pImport->invalidate( );
		updateCounts( );
		return true;
	}
	return false;
}

bool ImportsHandling::invalidateModule( ImportModuleThunk* pModule )
{
	if ( pModule )
	{
		for ( auto& [key, importThunk] : pModule->thunkList )
		{
			importThunk.invalidate( );
		}

		updateCounts( );
		return true;
	}

	return false;
}

bool ImportsHandling::setImport( ImportThunk* pImport, const WCHAR* moduleName, const CHAR* apiName, WORD ordinal, WORD hint, bool valid, bool suspect )
{
	if ( !pImport ) return false;

	ImportModuleThunk* pModule = getModuleThunk( pImport );
	if ( !pModule ) return false;

	wcsncpy_s( pImport->moduleName, moduleName, MAX_PATH - 1 );
	strncpy_s( pImport->name, apiName, MAX_PATH - 1 );
	pImport->moduleName[ MAX_PATH - 1 ] = L'\0'; // Ensure null-termination
	pImport->name[ MAX_PATH - 1 ] = '\0'; // Ensure null-termination
	pImport->ordinal = ordinal;
	pImport->hint = hint;
	pImport->valid = valid;
	pImport->suspect = suspect;

	if ( pModule->isValid( ) )
	{
		scanAndFixModuleList( );
		displayAllImports( );
	}
	else
	{
		updateCounts( );
	}
	return true;
}

ImportsHandling::Icon ImportsHandling::getAppropriateIcon( const ImportThunk* importThunk )
{
	return importThunk->valid ? ( importThunk->suspect ? iconWarning : iconCheck ) : iconError;
}

ImportsHandling::Icon ImportsHandling::getAppropriateIcon( bool valid )
{
	return valid ? iconCheck : iconError;
}

bool ImportsHandling::cutImport( ImportThunk* pImport )
{
	if ( !pImport ) return false;

	ImportModuleThunk* pModule = getModuleThunk( pImport );
	if ( !pModule ) return false;

	pModule->thunkList.erase( pImport->key );

	if ( pModule->thunkList.empty( ) )
	{
		moduleList.erase( pModule->key );
	}
	else
	{
		if ( pModule->isValid( ) && pModule->moduleName[ 0 ] == L'?' )
		{
			// Update pModule name
			wcsncpy_s( pModule->moduleName, pModule->thunkList.begin( )->second.moduleName, MAX_PATH - 1 );
			pModule->moduleName[ MAX_PATH - 1 ] = L'\0'; // Ensure null-termination
		}

		pModule->firstThunk = pModule->thunkList.begin( )->second.rva;
	}

	updateCounts( );

	return true;
}

bool ImportsHandling::cutModule( ImportModuleThunk* pModule )
{
	if ( !pModule ) return false;

	moduleList.erase( pModule->key );

	updateCounts( );

	return true;
}

void ImportsHandling::scanAndFixModuleList( )
{
	WCHAR prevModuleName[ MAX_PATH ] = { 0 };

	for ( auto& [key, moduleThunk] : moduleList )
	{
		for ( auto& [thunkKey, importThunk] : moduleThunk.thunkList )
		{
			if ( importThunk.moduleName[ 0 ] == 0 || importThunk.moduleName[ 0 ] == L'?' )
			{
				addNotFoundApiToModuleList( &importThunk );
			}
			else
			{
				if ( _wcsicmp( importThunk.moduleName, prevModuleName ) != 0 )
				{
					addModuleToModuleList( importThunk.moduleName, importThunk.rva );
				}

				addFunctionToModuleList( &importThunk );
			}

			wcsncpy_s( prevModuleName, importThunk.moduleName, MAX_PATH - 1 );
		}

		moduleThunk.thunkList.clear( );
	}

	moduleList = std::move( moduleListNew );
	moduleListNew.clear( );
}


bool ImportsHandling::findNewModules( std::map<DWORD_PTR, ImportThunk>& thunkList )
{
	throw std::exception( "The method or operation is not implemented." );
}

bool ImportsHandling::addModuleToModuleList( const WCHAR* moduleName, DWORD_PTR firstThunk )
{
	ImportModuleThunk pModule;

	pModule.firstThunk = firstThunk;
	wcscpy_s( pModule.moduleName, moduleName );

	pModule.key = pModule.firstThunk;
	moduleListNew[ pModule.key ] = std::move( pModule );
	return true;
}

bool ImportsHandling::isNewModule( const WCHAR* moduleName )
{
	return std::none_of( moduleListNew.begin( ), moduleListNew.end( ),
		[ moduleName ]( const auto& pair ) {
			return _wcsicmp( pair.second.moduleName, moduleName ) == 0;
		} );
}

void ImportsHandling::addUnknownModuleToModuleList( DWORD_PTR firstThunk )
{
	ImportModuleThunk pModule;

	pModule.firstThunk = firstThunk;
	wcsncpy_s( pModule.moduleName, L"?", _TRUNCATE );

	pModule.key = pModule.firstThunk;
	moduleListNew[ pModule.key ] = std::move( pModule );
}

bool ImportsHandling::addNotFoundApiToModuleList( const ImportThunk* apiNotFound )
{
	ImportThunk pImport{};
	ImportModuleThunk* pModule = nullptr;
	DWORD_PTR rva = apiNotFound->rva;

	auto it_module = std::find_if( moduleListNew.begin( ), moduleListNew.end( ),
		[ rva ]( const auto& pair ) { return rva < pair.second.firstThunk; } );

	if ( it_module != moduleListNew.begin( ) ) {
		--it_module; // Adjust to the correct module if not at the beginning
	}

	if ( moduleListNew.empty( ) || it_module->second.moduleName[ 0 ] != L'?' ) {
		addUnknownModuleToModuleList( apiNotFound->rva );
		pModule = &moduleListNew.find( rva )->second;
	}
	else {
		pModule = &it_module->second;
	}

	if ( !pModule ) {
		LOGS_DEBUG( "ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL, rva );
		return false;
	}

	pImport.suspect = true;
	pImport.valid = false;
	pImport.va = apiNotFound->va;
	pImport.rva = apiNotFound->rva;
	pImport.apiAddressVA = apiNotFound->apiAddressVA;
	pImport.ordinal = 0;

	wcscpy_s( pImport.moduleName, L"?" );
	strcpy_s( pImport.name, "?" );

	pImport.key = pImport.rva;
	pModule->thunkList[ pImport.key ] = std::move( pImport );
	return true;
}

bool ImportsHandling::addFunctionToModuleList( const ImportThunk* apiFound )
{
	ImportThunk pImport{};
	ImportModuleThunk* pModule = nullptr;

	auto it_module = std::find_if( moduleListNew.begin( ), moduleListNew.end( ),
		[ apiFound ]( const auto& pair ) { return apiFound->rva < pair.second.firstThunk; } );

	if ( it_module != moduleListNew.begin( ) ) {
		--it_module; // Adjust to the correct module if not at the beginning
	}

	if ( it_module == moduleListNew.end( ) ) {
		LOGS_DEBUG( "ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL, apiFound->rva );
		return false;
	}

	pModule = &it_module->second;

	pImport.suspect = apiFound->suspect;
	pImport.valid = apiFound->valid;
	pImport.va = apiFound->va;
	pImport.rva = apiFound->rva;
	pImport.apiAddressVA = apiFound->apiAddressVA;
	pImport.ordinal = apiFound->ordinal;
	pImport.hint = apiFound->hint;

	wcscpy_s( pImport.moduleName, apiFound->moduleName );
	strcpy_s( pImport.name, apiFound->name );

	pImport.key = pImport.rva;
	pModule->thunkList[ pImport.key ] = std::move( pImport );
	return true;
}


