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
	void iatAutosearchActionHandler( DWORD_PTR entrypoint );
	int setProcessById( std::uint32_t uProcessId );
private:
	void checkSuspendProcess( );
	bool isIATOutsidePeImage( DWORD_PTR addressIAT );
	bool getCurrentDefaultDumpFilename( );
	bool getCurrentModulePath( std::wstring& buffer );
	void setDialogIATAddressAndSize( DWORD_PTR addressIAT, DWORD sizeIAT );

	bool isProcessSuspended = false;
	ApiReader apiReader;
	ProcessLister processLister;
	Process* processPtr = nullptr;
	IATReferenceScan iatReferenceScan;
	ImportsHandling importsHandling;

	int Status = 0;

	DWORD_PTR m_addressIAT;
	DWORD m_sizeIAT;
	DWORD_PTR m_entrypoint = 0;


	std::wstring defaultFilename = L"";
	std::wstring defaultFilenameScy = L"";
};
