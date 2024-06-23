
#include "DeviceNameResolver.h"
#include "WinApi/ntos.h"
#include <memory>

DeviceNameResolver::DeviceNameResolver( )
{
    initDeviceNameList( );
}

DeviceNameResolver::~DeviceNameResolver( )
{
    deviceNameList.clear( );
}

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

bool DeviceNameResolver::resolveDeviceLongNameToShort( const TCHAR* sourcePath, TCHAR* targetPath )
{
    for ( std::uint32_t i = 0; i < deviceNameList.size( ); i++ )
    {
        if ( !_tcsnicmp( deviceNameList[ i ].longName, sourcePath, deviceNameList[ i ].longNameLength ) && sourcePath[ deviceNameList[ i ].longNameLength ] == TEXT( '\\' ) )
        {
            _tcscpy_s( targetPath, MAX_PATH, deviceNameList[ i ].shortName );
            _tcscat_s( targetPath, MAX_PATH, sourcePath + deviceNameList[ i ].longNameLength );
            return true;
        }
    }

    return false;
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


