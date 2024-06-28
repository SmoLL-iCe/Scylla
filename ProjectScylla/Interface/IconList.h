#pragma once
#include <windows.h>
#include <vector>
#include <memory>
#include <cstdint>
#include <string>
#include "Thirdparty/ImGui/imgui.h"

struct sIcon
{
	std::uint64_t ID;
	ImTextureID TextureID;
};

class IconList
{
public:
	IconList( const TCHAR* fileType = nullptr );
	~IconList( );
	sIcon getIcon( const std::wstring& wstrFilePath );
	sIcon getIcon( const std::uint64_t ID );
	sIcon extractIcon( const std::uint64_t ID, const std::wstring& wstrFilePath );
	sIcon extractIcon( const std::wstring& wstrFilePath );
	static bool ExtractIconFromFile( const TCHAR* filePath, ImTextureID& textureID );
	static bool ExtractIconFromExtension( const TCHAR* fileType, ImTextureID& textureID );
private:
	std::vector<sIcon> m_vIcons;
	ImTextureID m_defaultTexture = nullptr;
	TCHAR* m_pFileType = nullptr;
};

