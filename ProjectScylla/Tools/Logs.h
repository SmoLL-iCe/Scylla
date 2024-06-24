#pragma once
#include <Windows.h>
#include <iostream>

namespace nlog
{
	bool Init( );
	void SetConsoleColor( std::uint16_t color );
	bool Send( const char* szFormat, ... );
}

#define LOGS(fmt, ...) nlog::Send( fmt ## "\n", __VA_ARGS__)
//#define LOGS(fmt, ...) //nlog::Send( fmt ## "\n", __VA_ARGS__)



#define LOGS_IMPORT(fmt, ...) { nlog::SetConsoleColor( FOREGROUND_BLUE | FOREGROUND_INTENSITY ); \
	nlog::Send( fmt ## "\n", __VA_ARGS__ ); \
	nlog::SetConsoleColor(  FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE ); \
	}

//#define LOGS_DEBUG(fmt, ...) 


#define LOGS_DEBUG(fmt, ...) { nlog::SetConsoleColor( FOREGROUND_RED | FOREGROUND_INTENSITY ); \
	nlog::Send( fmt ## "\n", __VA_ARGS__ ); \
	nlog::SetConsoleColor(  FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE ); \
	}