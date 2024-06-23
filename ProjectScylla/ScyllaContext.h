#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <cstdint>
#include "ProcessAccessHelp.h"
#include "ProcessLister.h"
#include "ApiReader.h"
#include "IATReferenceScan.h"
#include "ImportsHandling.h"


class ScyllaContext
{
public:
	ScyllaContext( ) = default;
	ScyllaContext( std::uint32_t uProcessId );
	ScyllaContext( const std::wstring& strProcessName );
	~ScyllaContext( );

	bool setTargetModule( const std::wstring& strModuleName );
	bool setTargetModule( std::uintptr_t uBaseModule );
	bool setTargetModule( std::uintptr_t uBaseModule, std::uintptr_t uModuleSize, const std::wstring& strModulePath );
	void dumpActionHandler( );
	void dumpFixActionHandler( );
	void peRebuildActionHandler( );
	void getImportsActionHandler( );
	void iatAutosearchActionHandler( );
	int setProcessById( std::uint32_t uProcessId );
	void setDefaultFolder( const std::wstring& strNewFolder );

	std::uintptr_t m_addressIAT;
	std::uint32_t m_sizeIAT;
	ImportsHandling* getImportsHandling( );
private:
	void getPePreInfo( );
	void checkSuspendProcess( );
	bool isIATOutsidePeImage( std::uintptr_t uAddressIAT ) const;
	bool getCurrentDefaultDumpFilename( );
	bool getCurrentModulePath( std::wstring& outModulePath ) const;
	void setDialogIATAddressAndSize( std::uintptr_t uAddressIAT, std::uint32_t uSizeIAT );

	bool m_isProcessSuspended = false;
	ApiReader m_apiReader;
	ProcessLister m_processLister;
	Process m_processPtr = {};
	IATReferenceScan m_iatReferenceScan;
	ImportsHandling m_importsHandling;

	int Status = 0;

	std::uintptr_t m_entrypoint = 0;

	bool m_bIsModule = false;

	std::wstring m_strTargetFilePath = L"";
	std::wstring m_strDumpFullFilePath = L"";
	std::wstring m_strDumpFullFilePathScy = L"";
};
