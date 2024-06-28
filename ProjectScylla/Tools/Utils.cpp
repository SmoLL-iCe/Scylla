#include "Utils.h"
#include <algorithm>

std::wstring Utils::StrToLower( const std::wstring& s )
{
	std::wstring out = s;
	std::transform( out.begin( ), out.end( ), out.begin( ), ::tolower );
	return out;
}

std::string Utils::StrToLower( const std::string& s )
{
	std::string out = s;
	std::transform( out.begin( ), out.end( ), out.begin( ), ::tolower );
	return out;
}

std::string Utils::wstrToStr( const std::wstring& wstr ) {

	return std::string( wstr.begin( ), wstr.end( ) );
}

std::wstring Utils::strToWstr( const std::string& wstr ) {

	return std::wstring( wstr.begin( ), wstr.end( ) );
}