
#include "ScyllaContext.h"
#include <iostream>
#include "Interface/Interface.h"

int main()
{
    ProcessLister::setDebugPrivileges( );

    Interface::Initialize( );

    return getchar( );
}


