#pragma once

#include <windows.h>
#include <map>
#include <hash_map>

class CMultiSelectTreeViewCtrl;

class ImportThunk;
class ImportModuleThunk;

class ImportsHandling
{
public:
	std::map<DWORD_PTR, ImportModuleThunk> moduleList;
	std::map<DWORD_PTR, ImportModuleThunk> moduleListNew;

	ImportsHandling( );
	~ImportsHandling( );

	unsigned int thunkCount( ) const { return m_thunkCount; }
	unsigned int invalidThunkCount( ) const { return m_invalidThunkCount; }
	unsigned int suspectThunkCount( ) const { return m_suspectThunkCount; }

	ImportModuleThunk* getModuleThunk( ImportThunk* pImport );

	void displayAllImports( );
	void clearAllImports( );
	void selectImports( bool invalid, bool suspect );

	bool invalidateImport( ImportThunk* pImport );
	bool invalidateModule( ImportModuleThunk* pModule );
	bool setImport( ImportThunk* pImport, const WCHAR * moduleName, const CHAR * apiName, WORD ordinal = 0, WORD hint = 0, bool valid = true, bool suspect = false);
	bool cutImport( ImportThunk* pImport );
	bool cutModule( ImportModuleThunk* pModule );

	void scanAndFixModuleList( );
	void expandAllTreeNodes( );
	void collapseAllTreeNodes( );

	void updateCounts( );
private:
	DWORD numberOfFunctions;

	unsigned int m_thunkCount;
	unsigned int m_invalidThunkCount;
	unsigned int m_suspectThunkCount;

	// They have to be added to the image list in that order!
	enum Icon {
		iconCheck = 0,
		iconWarning,
		iconError
	};

	bool findNewModules( std::map<DWORD_PTR, ImportThunk>& thunkList );

	Icon getAppropriateIcon( const ImportThunk* importThunk );
	Icon getAppropriateIcon( bool valid );

	bool addModuleToModuleList( const WCHAR* moduleName, DWORD_PTR firstThunk );
	void addUnknownModuleToModuleList( DWORD_PTR firstThunk );
	bool addNotFoundApiToModuleList( const ImportThunk* apiNotFound );
	bool addFunctionToModuleList( const ImportThunk* apiFound );
	bool isNewModule( const WCHAR* moduleName );

	void changeExpandStateOfTreeNodes( UINT flag );

};
