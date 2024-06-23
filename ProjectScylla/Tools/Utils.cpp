#include "Utils.h"
#include <algorithm>

std::wstring Utils::StrToLower( std::wstring& s )
{
	std::transform( s.begin( ), s.end( ), s.begin( ), ::tolower );
	return s;
}


std::string Utils::wstrToStr( const std::wstring& wstr ) {

	return std::string( wstr.begin( ), wstr.end( ) );
}