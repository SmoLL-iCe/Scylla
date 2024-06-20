#include "Logs.h"
#include <stdio.h>

void nlog::SetConsoleColor( WORD color )
{
	HANDLE hConsoleOutput = GetStdHandle( STD_OUTPUT_HANDLE );
	SetConsoleTextAttribute( hConsoleOutput, color );
}

bool nlog::Init( )
{
	return true;
}

bool nlog::Send( const char* szFormat, ... )
{
	char MessageBuff[ 0x1000 ];

	ZeroMemory( MessageBuff, sizeof( MessageBuff ) );

	va_list va_a_list = { };

	va_start( va_a_list, szFormat );

	auto const length = _vsnprintf_s( MessageBuff, sizeof( MessageBuff ), _TRUNCATE, szFormat, va_a_list );

	va_end( va_a_list );

	std::cout << MessageBuff;

	return true;
}