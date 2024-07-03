
#include "DeviceNameResolver.h"
#include "WinApi/ntos.h"
#include <memory>
#include <string>

std::vector<HardDisk> deviceNameList;


void DeviceNameResolver::initDeviceNameList( )
{
    TCHAR shortName[ 3 ] = { 0 };
    TCHAR longName[ MAX_PATH ] = { 0 };
    HardDisk hardDisk { };

    shortName[ 1 ] = TEXT( ':' );

    deviceNameList.reserve( 26 );

    for ( TCHAR shortD = TEXT( 'a' ); shortD <= TEXT( 'z' ); shortD++ )
    {
        shortName[ 0 ] = shortD;
        if ( QueryDosDevice( shortName, longName, MAX_PATH ) > 0 )
        {
            hardDisk.shortName[ 0 ] = _totupper( shortD );
            hardDisk.shortName[ 1 ] = TEXT( ':' );
            hardDisk.shortName[ 2 ] = 0;

            hardDisk.longNameLength = _tcslen( longName );

            _tcscpy_s( hardDisk.longName, longName );
            deviceNameList.push_back( hardDisk );
        }
    }

    fixVirtualDevices( );
}

static 
std::wstring ExpandEnvironmentSystemRoot( const std::wstring& input )
{
    std::wstring output = L"%SystemRoot%" + input.substr( 11 );

    wchar_t buffer[ MAX_PATH ]{};

    DWORD result = ExpandEnvironmentStrings( output.c_str( ), buffer, MAX_PATH );
    if ( result == 0 || result > MAX_PATH )
    {
        return L"";
    }

    return std::wstring( buffer );
}

std::wstring DeviceNameResolver::resolveDeviceLongNameToShort( std::wstring sourcePath )
{
    if ( deviceNameList.empty( ) )
    {
        initDeviceNameList( );
    }

    if ( sourcePath.size( ) < 0x18 )
        return sourcePath;

    if ( sourcePath.find( L"SystemRoot" ) != std::wstring::npos )
    {
        return ExpandEnvironmentSystemRoot( sourcePath );
    }

    if ( sourcePath.find( LR"(\??\)" ) != std::wstring::npos )
    {
        return sourcePath.substr( 4 );
    }

    bool isDevice = sourcePath.find( L"Device" ) == 1;

    if ( !isDevice && sourcePath.find( L"HarddiskVolume" ) != 0 )
    {
        return sourcePath;
    }

    for ( const auto& device : deviceNameList )
    {
        std::wstring longName = ( isDevice ) ? device.longName : std::wstring( device.longName ).substr( 8 );
        size_t longNameLength = longName.length( );

        if ( sourcePath.compare( 0, longNameLength, longName ) == 0 && sourcePath[ longNameLength ] == L'\\' )
        {
            std::wstring targetPath = device.shortName + sourcePath.substr( longNameLength );
            return targetPath;
        }
    }

    return sourcePath;
}

void DeviceNameResolver::fixVirtualDevices( )
{
    const USHORT BufferSize = MAX_PATH * 2 * sizeof( wchar_t );
    wchar_t longCopy[ MAX_PATH ] = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING unicodeInput = { 0 };
    UNICODE_STRING unicodeOutput = { 0 };
    HANDLE hFile = 0;
    ULONG retLen = 0;

    auto unicodeOutputBuffer = std::make_unique<wchar_t[ ]>( BufferSize / sizeof( wchar_t ) );
    if ( !unicodeOutputBuffer )
        return;

    unicodeOutput.Buffer = unicodeOutputBuffer.get( );

    for ( auto& device : deviceNameList )
    {
        wcscpy_s( longCopy, device.longName );

        RtlInitUnicodeString( &unicodeInput, longCopy );
        InitializeObjectAttributes( &oa, &unicodeInput, 0, 0, 0 );

        if ( NT_SUCCESS( NtOpenSymbolicLinkObject( &hFile, SYMBOLIC_LINK_QUERY, &oa ) ) )
        {
            unicodeOutput.Length = BufferSize;
            unicodeOutput.MaximumLength = unicodeOutput.Length;
            ZeroMemory( unicodeOutput.Buffer, unicodeOutput.Length );

            if ( NT_SUCCESS( NtQuerySymbolicLinkObject( hFile, &unicodeOutput, &retLen ) ) )
            {
                HardDisk hardDisk {};

                hardDisk.longNameLength = wcslen( unicodeOutput.Buffer );

                wcscpy_s( hardDisk.shortName, device.shortName );

                wcscpy_s( hardDisk.longName, unicodeOutput.Buffer );

                deviceNameList.push_back( hardDisk );
            }

            NtClose( hFile );
        }
    }
}


