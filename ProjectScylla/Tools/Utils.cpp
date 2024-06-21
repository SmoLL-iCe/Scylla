#include "Utils.h"



std::string Utils::wstrToStr( const std::wstring& wstr ) {

	return std::string( wstr.begin( ), wstr.end( ) );
}