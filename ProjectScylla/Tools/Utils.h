#pragma once

#include <iostream>
#include <string>

namespace Utils { 
	std::wstring StrToLower( const std::wstring& s );
	std::string StrToLower( const std::string& s );
	std::string wstrToStr(const std::wstring& wstr);
}