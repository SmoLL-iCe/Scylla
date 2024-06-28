#include "IconList.h"
#include "CreateWindow.h"
#include "../Tools/Utils.h"

static 
uint64_t GenerateHash64( const std::wstring& wstr ) {

    const auto wstrLower  = Utils::StrToLower( wstr );

    std::hash<std::wstring> hasher;
    auto fullHash = hasher( wstr );

    uint64_t hash64 = static_cast<uint64_t>( fullHash );
    return hash64;
}

static 
bool HIconToImageData( HICON hIcon, std::vector<uint8_t>& imageData, int& width, int& height ) {
    ICONINFO iconInfo;
    BITMAP bm{ };

    if ( !GetIconInfo( hIcon, &iconInfo ) ) {
        return false;
    }

    if ( !GetObject( iconInfo.hbmColor, sizeof( bm ), &bm ) ) {
        DeleteObject( iconInfo.hbmColor );
        DeleteObject( iconInfo.hbmMask );
        return false;
    }

    width = bm.bmWidth;
    height = bm.bmHeight;

    HDC hdc = CreateCompatibleDC( NULL );
    BITMAPINFO bmi;
    ZeroMemory( &bmi, sizeof( bmi ) );
    bmi.bmiHeader.biSize = sizeof( BITMAPINFOHEADER );
    bmi.bmiHeader.biWidth = bm.bmWidth;
    bmi.bmiHeader.biHeight = -bm.bmHeight;  // top-down
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;  // 32 bits (RGBA)
    bmi.bmiHeader.biCompression = BI_RGB;

    imageData.resize( width * height * 4 );
    if ( GetDIBits( hdc, iconInfo.hbmColor, 0, height, imageData.data( ), &bmi, DIB_RGB_COLORS ) == 0 ) {
        DeleteObject( iconInfo.hbmColor );
        DeleteObject( iconInfo.hbmMask );
        DeleteDC( hdc );
        return false;
    }

    // Converte BGRA para RGBA
    for ( int i = 0; i < width * height; ++i ) {
        uint8_t temp = imageData[ i * 4 ];
        imageData[ i * 4 ] = imageData[ i * 4 + 2 ];
        imageData[ i * 4 + 2 ] = temp;
    }

    DeleteObject( iconInfo.hbmColor );
    DeleteObject( iconInfo.hbmMask );
    DeleteDC( hdc );

    return true;
}

static 
bool LoadIconToOpenGLTexture( HICON hIcon, GLuint* textureID ) {
    int width, height;
    std::vector<uint8_t> imageData;

    if ( !HIconToImageData( hIcon, imageData, width, height ) ) {
        return false;
    }

    return glWindow::LoadMemoryFile( imageData, ImVec2( width, height ), textureID );
}

bool IconList::ExtractIconFromFile( const TCHAR* filePath, ImTextureID& textureID ) {

    textureID = nullptr;

    int iconIndex = 0;

    HICON hIconLarge;
    HICON hIconSmall;

    int iconsExtracted = ExtractIconExW(
        filePath,
        iconIndex,
        &hIconLarge,
        &hIconSmall,
        1
    );

    if ( iconsExtracted > 0 ) {

        LoadIconToOpenGLTexture( hIconLarge, reinterpret_cast<GLuint*>( &textureID ) );
        DestroyIcon( hIconLarge );
        DestroyIcon( hIconSmall );

        if ( !textureID ) {
			return false;
		}
    }

    return ( iconsExtracted > 0 );
}

static 
bool GetFileTypeIcon( const TCHAR* fileType, HICON& hIconLarge ) {

    SHFILEINFO shFileInfo{};

    auto bRet = SHGetFileInfo( fileType, FILE_ATTRIBUTE_NORMAL, &shFileInfo, sizeof( SHFILEINFOA ), SHGFI_ICON | SHGFI_LARGEICON | SHGFI_USEFILEATTRIBUTES );

    if ( bRet ) {
        hIconLarge = shFileInfo.hIcon;
    }

    return bRet;
}

bool IconList::ExtractIconFromExtension( const TCHAR* fileType, ImTextureID& textureID ) {

    textureID = nullptr;

    HICON hIconLarge = nullptr;

    bool bRet = GetFileTypeIcon( fileType, hIconLarge );

    if ( bRet ) {

        LoadIconToOpenGLTexture( hIconLarge, reinterpret_cast<GLuint*>( &textureID ) );

        DestroyIcon( hIconLarge );

        if ( !textureID ) {
            return false;
        }
    }

    return bRet;
}

sIcon IconList::getIcon( const std::wstring& wstrFilePath ) {

    auto ID = GenerateHash64( wstrFilePath );

	return getIcon( ID ); 
 }

sIcon IconList::getIcon( const std::uint64_t ID ) {

    for ( auto& icon : m_vIcons ) {
        if ( icon.ID == ID ) {
			return icon;
		}
	}

    if ( !m_defaultTexture && m_pFileType )
    {
        IconList::ExtractIconFromExtension( m_pFileType, m_defaultTexture );
    }

    return {ID, m_defaultTexture };
}

sIcon IconList::extractIcon( const std::uint64_t ID, const std::wstring& wstrFilePath ) {

    for ( auto& icon : m_vIcons ) {
        if ( icon.ID == ID ) {
            return icon;
        }
    }

    sIcon icon = { ID, nullptr };

    if ( ExtractIconFromFile( wstrFilePath.c_str( ), icon.TextureID ) && icon.TextureID )
    {
        m_vIcons.push_back( icon );

        return icon;
    }

    if ( !m_defaultTexture && m_pFileType )
    {
        IconList::ExtractIconFromExtension( m_pFileType, m_defaultTexture );
    }

    icon.TextureID = m_defaultTexture;

    return icon;
}

sIcon IconList::extractIcon( const std::wstring& wstrFilePath ) {

    auto ID = GenerateHash64( wstrFilePath );

    return extractIcon( ID, wstrFilePath );
}

IconList::IconList( const TCHAR* fileType ) {

    m_pFileType = const_cast<TCHAR*>( fileType );

    if ( fileType )
    {
        IconList::ExtractIconFromExtension( fileType, m_defaultTexture );
    }
}

IconList::~IconList( )
{
    m_vIcons.clear( );
}