#pragma once
#include <windows.h>
#include <iostream>
#include <string>
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

	DWORD_PTR m_addressIAT;
	DWORD m_sizeIAT;
	ImportsHandling* getImportsHandling( );
private:
	void getPePreInfo( );
	void checkSuspendProcess( );
	bool isIATOutsidePeImage( DWORD_PTR addressIAT ) const;
	bool getCurrentDefaultDumpFilename( );
	bool getCurrentModulePath( std::wstring& outModulePath ) const;
	void setDialogIATAddressAndSize( DWORD_PTR addressIAT, DWORD sizeIAT );

	bool isProcessSuspended = false;
	ApiReader apiReader;
	ProcessLister processLister;
	Process processPtr = {};
	IATReferenceScan iatReferenceScan;
	ImportsHandling importsHandling;

	int Status = 0;

	DWORD_PTR m_entrypoint = 0;

	bool m_bIsModule = false;

	//std::uintptr_t m_uBaseModule = 0;
	//std::uintptr_t m_uModuleSize = 0;
	std::wstring strTargetFilePath = L"";
	std::wstring strDumpFullFilePath = L"";
	std::wstring strDumpFullFilePathScy = L"";
};
