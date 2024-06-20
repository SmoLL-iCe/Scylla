#pragma once
#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#include <Windows.h>
#include <map>
#include <hash_map>


class ImportThunk;
class ImportModuleThunk;

class ImportsHandling
{
public:
	std::map<DWORD_PTR, ImportModuleThunk> moduleList;
	std::map<DWORD_PTR, ImportModuleThunk> moduleListNew;

	~ImportsHandling();

	unsigned int thunkCount() const { return m_thunkCount; }
	unsigned int invalidThunkCount() const { return m_invalidThunkCount; }
	unsigned int suspectThunkCount() const { return m_suspectThunkCount; }

	void displayAllImports();
	void clearAllImports();

	//bool addImport(const WCHAR * moduleName, const CHAR * name, DWORD_PTR va, DWORD_PTR rva, WORD ordinal = 0, bool valid = true, bool suspect = false);
	//bool addModule(const WCHAR * moduleName, DWORD_PTR firstThunk);

	void scanAndFixModuleList();

private:
	DWORD numberOfFunctions;

	unsigned int m_thunkCount;
	unsigned int m_invalidThunkCount;
	unsigned int m_suspectThunkCount;

	struct TreeItemData
	{
		bool isModule;
		union
		{
			ImportModuleThunk * module;
			ImportThunk * import;
		};
	};

	WCHAR stringBuffer[600];

	// They have to be added to the image list in that order!
	enum Icon {
		iconCheck = 0,
		iconWarning,
		iconError
	};

	void updateCounts();

	Icon getAppropiateIcon(const ImportThunk * importThunk);
	Icon getAppropiateIcon(bool valid);

	bool addModuleToModuleList(const WCHAR * moduleName, DWORD_PTR firstThunk);
	void addUnknownModuleToModuleList(DWORD_PTR firstThunk);
	bool addNotFoundApiToModuleList(const ImportThunk * apiNotFound);
	bool addFunctionToModuleList(const ImportThunk * apiFound);
	bool isNewModule(const WCHAR * moduleName);
};
