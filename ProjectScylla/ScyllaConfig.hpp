#pragma once


namespace Config
{
	inline bool USE_PE_HEADER_FROM_DISK = 1;
	inline bool DEBUG_PRIVILEGE = 1;
	inline bool VALIDATE_PE = 1;
	inline bool DLL_INJECTION_AUTO_UNLOAD = 1;
	inline bool CREATE_BACKUP = 1;
	inline wchar_t IAT_SECTION_NAME[] = L".SCY";
	inline bool UPDATE_HEADER_CHECKSUM = 1;
	inline bool REMOVE_DOS_HEADER_STUB = 1;
	inline bool IAT_FIX_AND_OEP_FIX = 1;
	inline bool SUSPEND_PROCESS_FOR_DUMPING = 0;
	inline bool OriginalFirstThunk_SUPPORT = 1;

	inline bool USE_ADVANCED_IAT_SEARCH = 1;
	inline bool SCAN_DIRECT_IMPORTS = 1;;
	inline bool FIX_DIRECT_IMPORTS = 0;
	inline bool CREATE_NEW_IAT_IN_SECTION = 1;
	inline bool FIX_DIRECT_IMPORTS_NORMAL = 1;
	inline bool FIX_DIRECT_IMPORTS_UNIVERSAL = 1;
	inline bool DONT_CREATE_NEW_SECTION = 0;
	inline bool APIS_ALWAYS_FROM_DISK = 1;
}


