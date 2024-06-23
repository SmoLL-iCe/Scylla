
#include "Thirdparty/ImGui/imgui.h"
#include "Thirdparty/ImGui/imgui_impl_glfw.h"
#include "Thirdparty/ImGui/imgui_impl_opengl3.h"
#include <stdio.h>
#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <GLES2/gl2.h>
#endif
#include "Thirdparty/GLFW/glfw3.h"
#include "CreateWindow.h"
#include <cstdio>
#include <iostream>
#include <map>
#include <chrono>

using namespace std::chrono_literals;

constexpr auto ICON_MIN_FA = 0xe000;
constexpr auto ICON_MAX_FA = 0xf300;

#if defined(_MSC_VER) && (_MSC_VER >= 1900) && !defined(IMGUI_DISABLE_WIN32_FUNCTIONS)
#pragma comment(lib, "legacy_stdio_definitions")
#endif
#pragma comment(lib, "Opengl32.lib")

namespace ImGui
{
    void customStyleColorsLight( )
    {
    }
}

static
void glfw_error_callback2( int error, const char* pDescription )
{
    //logs( "glfw error %d: %s\n", error, pDescription );
}

glWindow* g_CurrentInstance = nullptr;
glWindow::glWindow( const char* pCaption, int nWidth, int nHeight ): m_nWidth( nWidth ), m_nHeight( nHeight ), m_pCaption( pCaption )
{
    g_CurrentInstance = this;
}

glWindow* glWindow::i( )
{
    return g_CurrentInstance;
}

void glWindow::create( )
{
    m_thread =  std::thread( runThread, this );

    std::this_thread::sleep_for( 1000ms );
}

inline static ImFont* addFontFromData( const void* pData, int const nSize, const char* pName, float const fSizePx, const ImWchar* pRanges = nullptr )
{
    auto font_cfg           = ImFontConfig( );
    font_cfg.OversampleH    = font_cfg.OversampleV = 1;
    font_cfg.PixelSnapH     = true;
    auto& io                = ImGui::GetIO( );
    // if ( font_cfg.Name[ 0 ] == '\0' )
    //     strcpy_s( font_cfg.Name, pName );

    if ( font_cfg.SizePixels <= 0.0f )
        font_cfg.SizePixels = fSizePx;

    io.IniFilename = ""; //"xxx__xx";//aquivo de config
    return io.Fonts->AddFontFromMemoryCompressedTTF( pData, nSize, font_cfg.SizePixels, &font_cfg, pRanges );
}

std::vector<ImFont*> glWindow::getFontsList( ) const
{
    return m_vFonts;
}

void cursorPositionCallback( GLFWwindow* pWindow, double dPosX, double dPosY );
void mouseButtonCallback( GLFWwindow* pWindow, int nButton, int nAction, int nMods );

void glWindow::routine( )
{
    glfwSetErrorCallback( glfw_error_callback2 );

    if ( !glfwInit( ) )
    {
        m_nStatus = 1;
        //logs(  "glfwInit fail"  );
        return;
    }

#if defined(IMGUI_IMPL_OPENGL_ES2)
    // GL ES 2.0 + GLSL 100
    const char* glsl_version = "#version 100";
    glfwWindowHint( GLFW_CONTEXT_VERSION_MAJOR, 2 );
    //glfwWindowHint( GLFW_CONTEXT_VERSION_MINOR, 0 );
    glfwWindowHint( GLFW_CLIENT_API, GLFW_OPENGL_ES_API );
#elif defined(__APPLE__)
    // GL 3.2 + GLSL 150
    const char* glsl_version = "#version 150";
    glfwWindowHint( GLFW_CONTEXT_VERSION_MAJOR, 3 );
    glfwWindowHint( GLFW_CONTEXT_VERSION_MINOR, 2 );
    glfwWindowHint( GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE );  // 3.2+ only
    glfwWindowHint( GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE );            // Required on Mac
#else
    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint( GLFW_CONTEXT_VERSION_MAJOR, 3 );
    glfwWindowHint( GLFW_CONTEXT_VERSION_MINOR, 0 );
    //glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
    //glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);            // 3.0+ only
#endif

    glfwWindowHint( GLFW_DECORATED, false );

    glfwWindowHint( GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE );

    m_pWindow = glfwCreateWindow( m_nWidth, m_nHeight, m_pCaption, nullptr, nullptr );

    if ( !m_pWindow )
    {
        m_nStatus = 2;
        //logs( "glfwCreateWindow fail" );
        return;
    }

    //SetLayeredWindowAttributes( h_wnd, 0xff77ff, 255, LWA_ALPHA );

    glfwSetWindowMonitor( m_pWindow, nullptr, 100, 100, m_nWidth, m_nHeight, 0 );

    glfwMakeContextCurrent( m_pWindow );

    glfwSwapInterval( 1 ); // Enable vsync

    glfwSetCursorPosCallback( m_pWindow, cursorPositionCallback );

    glfwSetMouseButtonCallback( m_pWindow, mouseButtonCallback );

    ImGui::CreateContext( );

    ImGui::customStyleColorsLight( );

    auto& style = ImGui::GetStyle( );

    style.FrameRounding         = 5.0f;
    style.WindowRounding        = 5.0f;
    style.WindowTitleAlign.x    = 0.5f;
    style.Alpha                 = 1.0f;

    ImGui_ImplGlfw_InitForOpenGL( m_pWindow, true );

    ImGui_ImplOpenGL3_Init( glsl_version );

    while ( !glfwWindowShouldClose( m_pWindow ) )
    {
        if ( m_bGoodbye )
            break;

        const auto visible = glfwGetWindowAttrib( m_pWindow, GLFW_VISIBLE );

        if ( visible )
        {
            glfwPollEvents( );

            ImGui_ImplOpenGL3_NewFrame( );

            ImGui_ImplGlfw_NewFrame( );

            ImGui::NewFrame( );

            if ( m_CallbackFrameControls )
                m_CallbackFrameControls( this );

            ImGui::Render( );


            int nDisplayW, nDisplayH;

            glfwGetFramebufferSize( m_pWindow, &nDisplayW, &nDisplayH );

            glViewport( 0, 0, nDisplayW, nDisplayH );

            glClearColor( 0, 0, 0, 0 );

            glClear( GL_COLOR_BUFFER_BIT );

            ImGui_ImplOpenGL3_RenderDrawData( ImGui::GetDrawData( ) );

            glfwSwapBuffers( m_pWindow );

            if ( !m_bShowWindow )
                close( );
        }

        std::this_thread::sleep_for( 10ms );

    }

    ImGui_ImplOpenGL3_Shutdown( );

    ImGui_ImplGlfw_Shutdown( );

    ImGui::DestroyContext( );

    glfwDestroyWindow( m_pWindow );

    glfwTerminate( );
}

void glWindow::goodbye( )
{
    m_bGoodbye = true;
}

void glWindow::close( ) const
{
    glfwSetWindowShouldClose( m_pWindow, GLFW_TRUE );

    exit( 0 );
}

void glWindow::runThread( glWindow* inst )
{
    inst->routine( );
}

void glWindow::setFrameControls( tFrame funcControls )
{
    m_CallbackFrameControls = funcControls;
}

void glWindow::setSize( int nWidth, int nHeight )
{
    glfwSetWindowSize( m_pWindow, nWidth, nHeight );

    m_nWidth = nWidth;

    m_nHeight = nHeight;
}

ImVec2 glWindow::getSize( ) const
{
    return { static_cast<float>( m_nWidth ) - static_cast<int>( m_fLeft ), static_cast<float>( m_nHeight ) - static_cast<int>( m_fTop ) };
}

void glWindow::setFramePos( float fLeft, float fTop )
{
    m_fTop = fTop;

    m_fLeft = fLeft;

    setSize( m_nWidth + static_cast<int>( fLeft ), m_nHeight + static_cast<int>( fTop ) );
}

ImVec2 glWindow::getFramePos( ) const
{
    return { m_fLeft, m_fTop };
}

void glWindow::center( ) const
{
    GLFWmonitor* pMonitor = glfwGetPrimaryMonitor( );

    const GLFWvidmode* pMode = glfwGetVideoMode( pMonitor );

    const auto nScreenCx = pMode->width;

    const auto nScreenCy = pMode->height;

    const auto nCenterX = ( nScreenCx / 2 ) - ( m_nWidth / 2 );

    const auto nCenterY = ( nScreenCy / 2 ) - ( m_nHeight / 2 );

    glfwSetWindowPos( m_pWindow, nCenterX, nCenterY );
}

static int nClickedXPos = 0;
static int nClickedYPos = 0;
static bool bMoveWindow = false;
static std::chrono::steady_clock::time_point lastTimePoint = {};

void cursorPositionCallback( GLFWwindow* pWindow, double dPosX, double dPosY )
{
    if ( bMoveWindow )
    {
        const auto nowTimePoint = std::chrono::high_resolution_clock::now( );

        const auto llElapsed = std::chrono::duration_cast<std::chrono::milliseconds>( nowTimePoint - lastTimePoint ).count( );

        if ( llElapsed < 100 )
            return;

        int x, y, nWidth, nHeight;

        glfwGetWindowPos( pWindow, &x, &y );

        glfwGetWindowSize( pWindow, &nWidth, &nHeight );

        const int nWindowX = x + static_cast<int>( dPosX ) - nClickedXPos;

        const int nWindowY = y + static_cast<int>( dPosY ) - nClickedYPos;

        glfwSetWindowPos( pWindow, nWindowX, nWindowY );
    }

}

void mouseButtonCallback( GLFWwindow* pWindow, int nButton, int nAction, int nMods )
{
    if ( nButton == GLFW_MOUSE_BUTTON_LEFT && nAction == GLFW_PRESS )
    {
        double dMouseX, dMouseY;

        glfwGetCursorPos( pWindow, &dMouseX, &dMouseY );

        const auto nTitleBarHeight = g_CurrentInstance->m_nHeight;

        nClickedXPos = static_cast<int>( dMouseX );

        nClickedYPos = static_cast<int>( dMouseY );

        if ( !ImGui::IsAnyItemHovered( ) ) {


            lastTimePoint = std::chrono::high_resolution_clock::now( );
            bMoveWindow = ( 
                static_cast<float>( nClickedYPos ) >= g_CurrentInstance->m_fTop 
                && static_cast<float>( nClickedYPos ) <= ( g_CurrentInstance->m_fTop + nTitleBarHeight ) 
                );
        }
    }
    else if ( nButton == GLFW_MOUSE_BUTTON_LEFT && nAction == GLFW_RELEASE )
    {
        bMoveWindow = false;
    }
}