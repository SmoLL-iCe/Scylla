#pragma once

#include <windows.h>
#include <cstdint>
#include <map>

class CMultiSelectTreeViewCtrl;

class ImportThunk;
class ImportModuleThunk;

class ImportsHandling
{
public:
	std::map<std::uintptr_t, ImportModuleThunk> vModuleList;
	std::map<std::uintptr_t, ImportModuleThunk> mpModuleListNew;

	ImportsHandling( );
	~ImportsHandling( );

	std::uint32_t thunkCount( ) const { return m_thunkCount; }
	std::uint32_t invalidThunkCount( ) const { return m_invalidThunkCount; }
	std::uint32_t suspectThunkCount( ) const { return m_suspectThunkCount; }

	ImportModuleThunk* getModuleThunk( ImportThunk* pImport );

	void displayAllImports( );
	void clearAllImports( );
	void selectImports( bool bInvalid, bool bSuspect );

	bool invalidateImport( ImportThunk* pImport );
	bool invalidateModule( ImportModuleThunk* pModule );
	bool setImport( ImportThunk* pImport, const wchar_t* pModuleName, const char* pApiName, std::uint16_t uOrdinal = 0, std::uint16_t uHint = 0, bool valid = true, bool suspect = false );
	bool cutImport( ImportThunk* pImport );
	bool cutModule( ImportModuleThunk* pModule );

	void scanAndFixModuleList( );
	void expandAllTreeNodes( );
	void collapseAllTreeNodes( );

	void updateCounts( );
private:
	std::uint32_t m_numberOfFunctions;

	std::uint32_t m_thunkCount;
	std::uint32_t m_invalidThunkCount;
	std::uint32_t m_suspectThunkCount;

	// They have to be added to the image list in that order!
	enum Icon {
		iconCheck = 0,
		iconWarning,
		iconError
	};

	bool findNewModules( std::map<std::uintptr_t, ImportThunk>& mpThunkList );

	Icon getAppropriateIcon( const ImportThunk* pImportThunk );
	Icon getAppropriateIcon( bool valid );

	bool addModuleToModuleList( const wchar_t* pModuleName, std::uintptr_t uFirstThunk );
	void addUnknownModuleToModuleList( std::uintptr_t uFirstThunk );
	bool addNotFoundApiToModuleList( const ImportThunk* pApiNotFound );
	bool addFunctionToModuleList( const ImportThunk* pApiFound );
	bool isNewModule( const wchar_t* pModuleName );

	void changeExpandStateOfTreeNodes( UINT flag );

};
