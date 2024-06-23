#pragma once

#include <windows.h>

class Logger
{
public:

	virtual void log( const wchar_t* format, ... );
	virtual void log( const char* format, ... );

protected:

	virtual void write( const wchar_t* str ) = 0;
	virtual void write( const char* str );
};

class FileLog : public Logger
{
public:

	FileLog( const wchar_t* fileName );

private:

	void write( const wchar_t* str );
	void write( const char* str );

	wchar_t pFilePath[ MAX_PATH ];
};

class ListboxLog : public Logger
{
public:

	ListboxLog( ): window( 0 ) { }
	ListboxLog( HWND window );

	void setWindow( HWND window );

private:

	void write( const wchar_t* str );
	//void write(const char * str);

	HWND window;
};
