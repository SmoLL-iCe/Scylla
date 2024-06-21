#include "ImportsHandling.h"
#include "Thunks.h"
#include "Architecture.h"
#include "Tools/Logs.h"

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
	std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin( );

	while ( iterator != thunkList.end( ) )
	{
		if ( iterator->second.valid == false )
		{
			return false;
		}
		iterator++;
	}

	return true;
}

DWORD_PTR ImportModuleThunk::getFirstThunk( ) const
{
	if ( thunkList.size( ) > 0 )
	{
		const std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin( );
		return iterator->first;
	}
	else
	{
		return 0;
	}
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
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	std::map<DWORD_PTR, ImportThunk>::iterator it_import;

	m_thunkCount = m_invalidThunkCount = m_suspectThunkCount = 0;

	it_module = moduleList.begin( );
	while ( it_module != moduleList.end( ) )
	{
		ImportModuleThunk& moduleThunk = it_module->second;

		it_import = moduleThunk.thunkList.begin( );
		while ( it_import != moduleThunk.thunkList.end( ) )
		{
			ImportThunk& importThunk = it_import->second;

			m_thunkCount++;
			if ( !importThunk.valid )
				m_invalidThunkCount++;
			else if ( importThunk.suspect )
				m_suspectThunkCount++;

			it_import++;
		}

		it_module++;
	}
}

/*bool ImportsHandling::addImport(const WCHAR * moduleName, const CHAR * name, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect)
{
	ImportThunk pImport;
	ImportModuleThunk  * pModule = 0;
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;

	if (moduleList.size() > 1)
	{
		iterator1 = moduleList.begin();
		while (iterator1 != moduleList.end())
		{
			if (rva >= iterator1->second.firstThunk)
			{
				iterator1++;
				if (iterator1 == moduleList.end())
				{
					iterator1--;
					pModule = &(iterator1->second);
					break;
				}
				else if (rva < iterator1->second.firstThunk)
				{
					iterator1--;
					pModule = &(iterator1->second);
					break;
				}
			}
		}
	}
	else
	{
		iterator1 = moduleList.begin();
		pModule = &(iterator1->second);
	}

	if (!pModule)
	{
		Scylla::debugLog.log(L"ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL, rva);
		return false;
	}

	//TODO
	pImport.suspect = true;
	pImport.valid = false;
	pImport.va = va;
	pImport.rva = rva;
	pImport.ordinal = ordinal;

	wcscpy_s(pImport.moduleName, MAX_PATH, moduleName);
	strcpy_s(pImport.name, MAX_PATH, name);

	pModule->thunkList.insert(std::pair<DWORD_PTR,ImportThunk>(pImport.rva, pImport));

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
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	std::map<DWORD_PTR, ImportThunk>::iterator it_import;

	it_module = moduleList.begin( );
	while ( it_module != moduleList.end( ) )
	{
		ImportModuleThunk& moduleThunk = it_module->second;

		moduleThunk.key = moduleThunk.firstThunk; // This belongs elsewhere...
		//moduleThunk.hTreeItem = addDllToTreeView( TreeImports, &moduleThunk );

		it_import = moduleThunk.thunkList.begin( );
		while ( it_import != moduleThunk.thunkList.end( ) )
		{
			ImportThunk& importThunk = it_import->second;

			importThunk.key = importThunk.rva; // This belongs elsewhere...
			//importThunk.hTreeItem = addApiToTreeView( TreeImports, moduleThunk.hTreeItem, &importThunk );

			it_import++;
		}

		it_module++;
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
		std::map<DWORD_PTR, ImportThunk>::iterator it_import;

		it_import = pModule->thunkList.begin( );
		while ( it_import != pModule->thunkList.end( ) )
		{
			ImportThunk* pImport = &it_import->second;

			pImport->invalidate( );

			it_import++;
		}

		updateCounts( );

		return true;
	}

	return false;
}

bool ImportsHandling::setImport( ImportThunk* pImport, const WCHAR* moduleName, const CHAR* apiName, WORD ordinal, WORD hint, bool valid, bool suspect )
{
	if ( pImport )
	{

		ImportModuleThunk* pModule = getModuleThunk( pImport );

		if ( pModule )
		{

			wcscpy_s( pImport->moduleName, moduleName );
			strcpy_s( pImport->name, apiName );
			pImport->ordinal = ordinal;
			//pImport->apiAddressVA = api->va; //??
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
		
	}
	return false;
}


ImportsHandling::Icon ImportsHandling::getAppropriateIcon( const ImportThunk* importThunk )
{
	if ( importThunk->valid )
	{
		if ( importThunk->suspect )
		{
			return iconWarning;
		}
		else
		{
			return iconCheck;
		}
	}
	else
	{
		return iconError;
	}
}

ImportsHandling::Icon ImportsHandling::getAppropriateIcon( bool valid )
{
	if ( valid )
	{
		return iconCheck;
	}
	else
	{
		return iconError;
	}
}

bool ImportsHandling::cutImport( ImportThunk* pImport )
{
	if ( pImport )
	{
		ImportModuleThunk* pModule = getModuleThunk( pImport );

		if ( pModule )
		{
			pModule->thunkList.erase( pImport->key );

			pImport = 0;

			if ( pModule->thunkList.empty( ) )
			{
				moduleList.erase( pModule->key );

				pModule = 0;
			}
			else
			{
				if ( pModule->isValid( ) && pModule->moduleName[ 0 ] == L'?' )
				{
					//update pModule name
					wcscpy_s( pModule->moduleName, pModule->thunkList.begin( )->second.moduleName );
				}

				pModule->firstThunk = pModule->thunkList.begin( )->second.rva;
			}

			updateCounts( );

			return true;
		}
		
	}
	return false;
}

bool ImportsHandling::cutModule( ImportModuleThunk* pModule )
{
	if ( pModule )
	{
		moduleList.erase( pModule->key );

		pModule = 0;

		updateCounts( );

		return true;
	}
	return false;
}

void ImportsHandling::scanAndFixModuleList( )
{
	WCHAR prevModuleName[ MAX_PATH ] = { 0 };
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	std::map<DWORD_PTR, ImportThunk>::iterator it_import;

	it_module = moduleList.begin( );
	while ( it_module != moduleList.end( ) )
	{
		ImportModuleThunk& moduleThunk = it_module->second;

		it_import = moduleThunk.thunkList.begin( );

		ImportThunk* importThunkPrev;
		importThunkPrev = &it_import->second;

		while ( it_import != moduleThunk.thunkList.end( ) )
		{
			ImportThunk& importThunk = it_import->second;

			if ( importThunk.moduleName[ 0 ] == 0 || importThunk.moduleName[ 0 ] == L'?' )
			{
				addNotFoundApiToModuleList( &importThunk );
			}
			else
			{

				if ( _wcsicmp( importThunk.moduleName, prevModuleName ) )
				{
					addModuleToModuleList( importThunk.moduleName, importThunk.rva );
				}

				addFunctionToModuleList( &importThunk );
			}

			wcscpy_s( prevModuleName, importThunk.moduleName );
			it_import++;
		}

		moduleThunk.thunkList.clear( );

		it_module++;
	}

	moduleList = moduleListNew;
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
	moduleListNew[ pModule.key ] = pModule;
	return true;
}

bool ImportsHandling::isNewModule( const WCHAR* moduleName )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;

	it_module = moduleListNew.begin( );
	while ( it_module != moduleListNew.end( ) )
	{
		if ( !_wcsicmp( it_module->second.moduleName, moduleName ) )
		{
			return false;
		}

		it_module++;
	}

	return true;
}

void ImportsHandling::addUnknownModuleToModuleList( DWORD_PTR firstThunk )
{
	ImportModuleThunk pModule;

	pModule.firstThunk = firstThunk;
	wcscpy_s( pModule.moduleName, L"?" );

	pModule.key = pModule.firstThunk;
	moduleListNew[ pModule.key ] = pModule;
}

bool ImportsHandling::addNotFoundApiToModuleList( const ImportThunk* apiNotFound )
{
	ImportThunk pImport{ };
	ImportModuleThunk* pModule = 0;
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	DWORD_PTR rva = apiNotFound->rva;

	if ( moduleListNew.size( ) > 0 )
	{
		it_module = moduleListNew.begin( );
		while ( it_module != moduleListNew.end( ) )
		{
			if ( rva >= it_module->second.firstThunk )
			{
				it_module++;
				if ( it_module == moduleListNew.end( ) )
				{
					it_module--;
					//new unknown pModule
					if ( it_module->second.moduleName[ 0 ] == L'?' )
					{
						pModule = &( it_module->second );
					}
					else
					{
						addUnknownModuleToModuleList( apiNotFound->rva );
						pModule = &( moduleListNew.find( rva )->second );
					}

					break;
				}
				else if ( rva < it_module->second.firstThunk )
				{
					it_module--;
					pModule = &( it_module->second );
					break;
				}
			}
			else
			{
				LOGS_DEBUG("Error iterator1 != (*moduleThunkList).end()" );
				break;
			}
		}
	}
	else
	{
		//new unknown pModule
		addUnknownModuleToModuleList( apiNotFound->rva );
		pModule = &( moduleListNew.find( rva )->second );
	}

	if ( !pModule )
	{
		LOGS_DEBUG("ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL, rva );
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
	pModule->thunkList[ pImport.key ] = pImport;
	return true;
}

bool ImportsHandling::addFunctionToModuleList( const ImportThunk* apiFound )
{
	ImportThunk pImport{ };
	ImportModuleThunk* pModule = 0;
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;

	if ( moduleListNew.size( ) > 1 )
	{
		it_module = moduleListNew.begin( );
		while ( it_module != moduleListNew.end( ) )
		{
			if ( apiFound->rva >= it_module->second.firstThunk )
			{
				it_module++;
				if ( it_module == moduleListNew.end( ) )
				{
					it_module--;
					pModule = &( it_module->second );
					break;
				}
				else if ( apiFound->rva < it_module->second.firstThunk )
				{
					it_module--;
					pModule = &( it_module->second );
					break;
				}
			}
			else
			{
				LOGS_DEBUG("Error iterator1 != moduleListNew.end()" );
				break;
			}
		}
	}
	else
	{
		it_module = moduleListNew.begin( );
		pModule = &( it_module->second );
	}

	if ( !pModule )
	{
		LOGS_DEBUG("ImportsHandling::addFunction pModule not found rva " PRINTF_DWORD_PTR_FULL, apiFound->rva );
		return false;
	}


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
	pModule->thunkList[ pImport.key ] = pImport;
	return true;
}

