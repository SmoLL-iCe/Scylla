#pragma once

#include <Windows.h>
#include <vector>
#include <tchar.h>
#include <string>

class HardDisk {
public:
	TCHAR shortName[ 3 ];
	TCHAR longName[ MAX_PATH ];
	std::size_t longNameLength;
};

namespace DeviceNameResolver
{
	std::wstring resolveDeviceLongNameToShort( std::wstring sourcePath );
	void initDeviceNameList( );
	void fixVirtualDevices( );
};

