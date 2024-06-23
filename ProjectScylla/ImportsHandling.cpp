#include "ImportsHandling.h"
#include "Thunks.h"
#include "Architecture.h"
#include "Tools/Logs.h"
#include <algorithm>

void ImportThunk::invalidate( )
{
	uOrdinal = 0;
	uHint = 0;
	bValid = false;
	bSuspect = false;
	pModuleName[ 0 ] = 0;
	name[ 0 ] = 0;
}

bool ImportModuleThunk::isValid( ) const
{
	return std::all_of( mpThunkList.begin( ), mpThunkList.end( ), [ ]( const auto& pair ) {
		return pair.second.bValid;
		} );
}

std::uintptr_t ImportModuleThunk::getFirstThunk( ) const
{
	if ( !mpThunkList.empty( ) )
	{
		return mpThunkList.begin( )->first;
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
	for ( auto& [uKey, moduleThunk] : vModuleList )
	{
		for ( auto& [uKey, importThunk] : moduleThunk.mpThunkList )
		{
			if ( importThunk.uKey == pImport->uKey )
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

	for ( const auto& [uKey, moduleThunk] : vModuleList )
	{
		for ( const auto& [thunkKey, importThunk] : moduleThunk.mpThunkList )
		{
			m_thunkCount++;
			if ( !importThunk.bValid )
				m_invalidThunkCount++;
			else if ( importThunk.bSuspect )
				m_suspectThunkCount++;
		}
	}
}

/*
bool ImportsHandling::addImport(const wchar_t * pModuleName, const char * name, std::uintptr_t VA, std::uintptr_t RVA, std::uint16_t uOrdinal, bool bValid, bool bSuspect)
{
	ImportModuleThunk* pModule = nullptr;

	if (!vModuleList.empty())
	{
		auto it = std::find_if(vModuleList.begin(), vModuleList.end(), [RVA](const std::pair<std::uintptr_t, ImportModuleThunk>& modulePair) {
			return RVA >= modulePair.second.uFirstThunk && (modulePair.first == vModuleList.rbegin()->first || RVA < std::next(&modulePair)->second.uFirstThunk);
		});

		if (it != vModuleList.end())
		{
			pModule = &(it->second);
		}
	}

	if (!pModule)
	{
		Scylla::debugLog.log(L"ImportsHandling::addFunction pModule not found RVA " PRINTF_DWORD_PTR_FULL, RVA);
		return false;
	}

	ImportThunk pImport;
	pImport.bSuspect = bSuspect;
	pImport.bValid = bValid;
	pImport.VA = VA;
	pImport.RVA = RVA;
	pImport.uOrdinal = uOrdinal;

	wcscpy_s(pImport.pModuleName, MAX_PATH, pModuleName);
	strcpy_s(pImport.name, MAX_PATH, name);

	pModule->mpThunkList.insert(std::make_pair(pImport.RVA, pImport));

	return true;
}

*/

/*
bool ImportsHandling::addModule(const wchar_t * pModuleName, std::uintptr_t uFirstThunk)
{
	ImportModuleThunk pModule;

	pModule.uFirstThunk = uFirstThunk;
	wcscpy_s(pModule.pModuleName, MAX_PATH, pModuleName);

	vModuleList.insert(std::pair<std::uintptr_t,ImportModuleThunk>(uFirstThunk,pModule));

	return true;
}
*/

void ImportsHandling::displayAllImports( )
{
	for ( auto& [uKey, moduleThunk] : vModuleList )
	{
		moduleThunk.uKey = moduleThunk.uFirstThunk; // This belongs elsewhere...
		//moduleThunk.hTreeItem = addDllToTreeView(TreeImports, &moduleThunk);

		for ( auto& [thunkKey, importThunk] : moduleThunk.mpThunkList )
		{
			importThunk.uKey = importThunk.uRVA; // This belongs elsewhere...
			//importThunk.hTreeItem = addApiToTreeView(TreeImports, moduleThunk.hTreeItem, &importThunk);
		}
	}

	updateCounts( );
}

void ImportsHandling::clearAllImports( )
{
	vModuleList.clear( );
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
		for ( auto& [uKey, importThunk] : pModule->mpThunkList )
		{
			importThunk.invalidate( );
		}

		updateCounts( );
		return true;
	}

	return false;
}

bool ImportsHandling::setImport( ImportThunk* pImport, const wchar_t* pModuleName, const char* pApiName, std::uint16_t uOrdinal, std::uint16_t uHint, bool bValid, bool bSuspect )
{
	if ( !pImport ) return false;

	ImportModuleThunk* pModuleThunk = getModuleThunk( pImport );
	if ( !pModuleThunk ) return false;

	wcsncpy_s( pImport->pModuleName, pModuleName, MAX_PATH - 1 );
	strncpy_s( pImport->name, pApiName, MAX_PATH - 1 );
	pImport->pModuleName[ MAX_PATH - 1 ] = L'\0'; // Ensure null-termination
	pImport->name[ MAX_PATH - 1 ] = '\0'; // Ensure null-termination
	pImport->uOrdinal = uOrdinal;
	pImport->uHint = uHint;
	pImport->bValid = bValid;
	pImport->bSuspect = bSuspect;

	if ( pModuleThunk->isValid( ) )
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

ImportsHandling::Icon ImportsHandling::getAppropriateIcon( const ImportThunk* pImportThunk )
{
	return pImportThunk->bValid ? ( pImportThunk->bSuspect ? iconWarning : iconCheck ) : iconError;
}

ImportsHandling::Icon ImportsHandling::getAppropriateIcon( bool bValid )
{
	return bValid ? iconCheck : iconError;
}

bool ImportsHandling::cutImport( ImportThunk* pImport )
{
	if ( !pImport ) return false;

	ImportModuleThunk* pModule = getModuleThunk( pImport );
	if ( !pModule ) return false;

	pModule->mpThunkList.erase( pImport->uKey );

	if ( pModule->mpThunkList.empty( ) )
	{
		vModuleList.erase( pModule->uKey );
	}
	else
	{
		if ( pModule->isValid( ) && pModule->pModuleName[ 0 ] == L'?' )
		{
			// Update pModule name
			wcsncpy_s( pModule->pModuleName, pModule->mpThunkList.begin( )->second.pModuleName, MAX_PATH - 1 );
			pModule->pModuleName[ MAX_PATH - 1 ] = L'\0'; // Ensure null-termination
		}

		pModule->uFirstThunk = pModule->mpThunkList.begin( )->second.uRVA;
	}

	updateCounts( );

	return true;
}

bool ImportsHandling::cutModule( ImportModuleThunk* pModule )
{
	if ( !pModule ) return false;

	vModuleList.erase( pModule->uKey );

	updateCounts( );

	return true;
}

void ImportsHandling::scanAndFixModuleList( )
{
	wchar_t prevModuleName[ MAX_PATH ] = { 0 };

	for ( auto& [uKey, moduleThunk] : vModuleList )
	{
		for ( auto& [thunkKey, importThunk] : moduleThunk.mpThunkList )
		{
			if ( importThunk.pModuleName[ 0 ] == 0 || importThunk.pModuleName[ 0 ] == L'?' )
			{
				addNotFoundApiToModuleList( &importThunk );
			}
			else
			{
				if ( _wcsicmp( importThunk.pModuleName, prevModuleName ) != 0 )
				{
					addModuleToModuleList( importThunk.pModuleName, importThunk.uRVA );
				}

				addFunctionToModuleList( &importThunk );
			}

			wcsncpy_s( prevModuleName, importThunk.pModuleName, MAX_PATH - 1 );
		}

		moduleThunk.mpThunkList.clear( );
	}

	vModuleList = std::move( mpModuleListNew );
	mpModuleListNew.clear( );
}


bool ImportsHandling::findNewModules( std::map<std::uintptr_t, ImportThunk>& mpThunkList )
{
	throw std::exception( "The method or operation is not implemented." );
}

bool ImportsHandling::addModuleToModuleList( const wchar_t* pModuleName, std::uintptr_t uFirstThunk )
{
	ImportModuleThunk ModuleThunk;

	ModuleThunk.uFirstThunk = uFirstThunk;
	wcscpy_s( ModuleThunk.pModuleName, pModuleName );

	ModuleThunk.uKey = ModuleThunk.uFirstThunk;
	mpModuleListNew[ ModuleThunk.uKey ] = std::move( ModuleThunk );
	return true;
}

bool ImportsHandling::isNewModule( const wchar_t* pModuleName )
{
	return std::none_of( mpModuleListNew.begin( ), mpModuleListNew.end( ),
		[pModuleName]( const auto& pair ) {
			return _wcsicmp( pair.second.pModuleName, pModuleName ) == 0;
		} );
}

void ImportsHandling::addUnknownModuleToModuleList( std::uintptr_t uFirstThunk )
{
	ImportModuleThunk ModuleThunk;

	ModuleThunk.uFirstThunk = uFirstThunk;
	wcsncpy_s( ModuleThunk.pModuleName, L"?", _TRUNCATE );

	ModuleThunk.uKey = ModuleThunk.uFirstThunk;
	mpModuleListNew[ ModuleThunk.uKey ] = std::move( ModuleThunk );
}

bool ImportsHandling::addNotFoundApiToModuleList( const ImportThunk* pApiNotFound )
{
	ImportThunk ImportThk {};
	ImportModuleThunk* pModuleThunk = nullptr;
	std::uintptr_t RVA = pApiNotFound->uRVA;

	auto itModule = std::find_if( mpModuleListNew.begin( ), mpModuleListNew.end( ),
		[RVA]( const auto& pair ) { return RVA < pair.second.uFirstThunk; } );

	if ( itModule != mpModuleListNew.begin( ) ) {
		--itModule; // Adjust to the correct pModule if not at the beginning
	}

	if ( mpModuleListNew.empty( ) || itModule->second.pModuleName[ 0 ] != L'?' ) {
		addUnknownModuleToModuleList( pApiNotFound->uRVA );
		pModuleThunk = &mpModuleListNew.find( RVA )->second;
	}
	else {
		pModuleThunk = &itModule->second;
	}

	if ( !pModuleThunk ) {
		LOGS_DEBUG( "ImportsHandling::addFunction pModule not found RVA " PRINTF_DWORD_PTR_FULL, RVA );
		return false;
	}

	ImportThk.bSuspect = true;
	ImportThk.bValid = false;
	ImportThk.uVA = pApiNotFound->uVA;
	ImportThk.uRVA = pApiNotFound->uRVA;
	ImportThk.uApiAddressVA = pApiNotFound->uApiAddressVA;
	ImportThk.uOrdinal = 0;

	wcscpy_s( ImportThk.pModuleName, L"?" );
	strcpy_s( ImportThk.name, "?" );

	ImportThk.uKey = ImportThk.uRVA;
	pModuleThunk->mpThunkList[ ImportThk.uKey ] = std::move( ImportThk );
	return true;
}

bool ImportsHandling::addFunctionToModuleList( const ImportThunk* pApiFound )
{
	ImportThunk ImportThk {};
	ImportModuleThunk* pModule = nullptr;

	auto itModule = std::find_if( mpModuleListNew.begin( ), mpModuleListNew.end( ),
		[pApiFound]( const auto& pair ) { return pApiFound->uRVA < pair.second.uFirstThunk; } );

	if ( itModule != mpModuleListNew.begin( ) ) {
		--itModule; // Adjust to the correct pModule if not at the beginning
	}

	if ( itModule == mpModuleListNew.end( ) ) {
		LOGS_DEBUG( "ImportsHandling::addFunction pModule not found RVA " PRINTF_DWORD_PTR_FULL, pApiFound->RVA );
		return false;
	}

	pModule = &itModule->second;

	ImportThk.bSuspect = pApiFound->bSuspect;
	ImportThk.bValid = pApiFound->bValid;
	ImportThk.uVA = pApiFound->uVA;
	ImportThk.uRVA = pApiFound->uRVA;
	ImportThk.uApiAddressVA = pApiFound->uApiAddressVA;
	ImportThk.uOrdinal = pApiFound->uOrdinal;
	ImportThk.uHint = pApiFound->uHint;

	wcscpy_s( ImportThk.pModuleName, pApiFound->pModuleName );
	strcpy_s( ImportThk.name, pApiFound->name );

	ImportThk.uKey = ImportThk.uRVA;
	pModule->mpThunkList[ ImportThk.uKey ] = std::move( ImportThk );
	return true;
}


