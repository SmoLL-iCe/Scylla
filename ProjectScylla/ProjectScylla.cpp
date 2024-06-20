
#include "ScyllaContext.h"
#include <iostream>
#include "Interface/FrmMain.h"

int main()
{
    std::cout << "Hello World!\n";

    gui_init( );

    //ScyllaContext scyllaCtx = ScyllaContext( L"test_s64.exe" );

    //if ( scyllaCtx.setTargetModule( L"test_s64.exe" ) ) { 
    //
    //}

    //scyllaCtx.dumpActionHandler( );

    return getchar( );
}


