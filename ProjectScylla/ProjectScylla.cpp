
#include "ScyllaContext.h"
#include <iostream>
#include "Interface/FrmMain.h"

int main()
{
    ProcessLister::setDebugPrivileges( );

    Interface::Initialize( );

    return getchar( );
}


