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

std::string Utils::uintPtrToHex( std::uintptr_t value ) {

	char hexString[ 19 ]{};
	snprintf( hexString, sizeof( hexString ), (sizeof( std::uintptr_t ) == 8 ) ? "%016llX" : "%08X", value );

	return std::string( hexString );
}

std::uintptr_t Utils::hexToUintPtr( const std::string& hex ) {

	std::uintptr_t value = 0;
#ifdef _WIN64
	return std::stoull( hex, &value, 16 );
#else
	return std::stoul( hex, &value, 8 );
#endif // _WIN64
}