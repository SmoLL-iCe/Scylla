#include "Interface.h"
#include "GuiContext.h"

std::unique_ptr<GuiContext> guiContext = nullptr;

static 
void FrameControls( glWindow* pWindowInstance )
{
    if ( guiContext )
        guiContext->Render( );
}

glWindow* window = nullptr;

void Interface::Initialize( )
{

    window = new glWindow( "", 10, 10 );

    window->create( );

    window->setFrameControls( FrameControls );

    std::this_thread::sleep_for( 100ms );

    window->center( );


    guiContext = std::make_unique<GuiContext>( window );

    while ( true )
    {
        std::this_thread::sleep_for( 100ms );
    }
}
