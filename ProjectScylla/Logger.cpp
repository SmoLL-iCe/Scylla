#include "Logger.h"
#include <shlwapi.h>
#include <cstdio>
#include <atlbase.h> 
#include <atlconv.h>

//extern bool IsDllMode;

void Logger::log( const wchar_t* format, ... )
{
	static wchar_t buf[ 300 ];

	if ( !format )
		return;

	va_list va_alist;
	va_start ( va_alist, format );
	_vsnwprintf_s( buf, _countof( buf ) - 1, format, va_alist );
	va_end ( va_alist );

	write( buf );
}

void Logger::log( const char* format, ... )
{
	static char buf[ 300 ];

	if ( !format )
		return;

	va_list va_alist;
	va_start ( va_alist, format );
	_vsnprintf_s( buf, _countof( buf ) - 1, format, va_alist );
	va_end ( va_alist );

	write( buf );
}

void Logger::write( const char* str )
{
	write( ATL::CA2W( str ) );
}

FileLog::FileLog( const wchar_t* fileName )
{
	GetModuleFileName( 0, this->pFilePath, _countof( this->pFilePath ) );
	PathRemoveFileSpec( this->pFilePath );
	PathAppend( this->pFilePath, fileName );
}

void FileLog::write( const char* str )
{
	/*
	std::wofstream file(pFilePath, std::wofstream::app);
	if(!file.fail())
	{
		file << str << std::endl;
	}
	*/

	FILE* pFile = 0;
	if ( _wfopen_s( &pFile, pFilePath, L"a" ) == 0 )
	{
		fputs( str, pFile );
		fputs( "\r\n", pFile );
		fclose( pFile );
	}
}

void FileLog::write( const wchar_t* str )
{
	/*
	std::wofstream file(pFilePath, std::wofstream::app);
	if(!file.fail())
	{
		file << str << std::endl;
	}
	*/

	FILE* pFile = 0;
	if ( _wfopen_s( &pFile, pFilePath, L"a" ) == 0 )
	{
		fputws( str, pFile );
		fputws( L"\r\n", pFile );
		fclose( pFile );
	}
}

void ListboxLog::setWindow( HWND window )
{
	this->window = window;
}

void ListboxLog::write( const wchar_t* str )
{
	//if (IsDllMode == false)
	//{
	//	LRESULT index = SendMessageW(window, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(str));
	//	SendMessage(window, LB_SETCURSEL, index, 0);
	//	UpdateWindow(window);
	//}
}
