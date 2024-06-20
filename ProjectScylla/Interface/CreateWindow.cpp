
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

    void custom_StyleColorsLight( )
    {
        //auto* style                             = &ImGui::GetStyle();
        //auto* colors                            = style->Colors;

        //style->FrameBorderSize                  = 0;
        //style->ChildBorderSize                  = 0;
        //style->WindowBorderSize                 = 1.f;
        //style->WindowPadding = { 0,0 };
        //

        //colors[ImGuiCol_Text]                   = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        //colors[ImGuiCol_TextDisabled]           = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
        //colors[ImGuiCol_WindowBg]               = gui::hex2float_color( 0x0c1924 );
        //colors[ImGuiCol_ChildBg]                = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
        //colors[ImGuiCol_PopupBg]                = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
        //colors[ImGuiCol_Border]                 = gui::hex2float_color( 0x883db2 );
        //colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        //colors[ImGuiCol_FrameBg]                = gui::hex2float_color( 0x405c94 ); //  
        //colors[ImGuiCol_FrameBgHovered]         = gui::hex2float_color( 0xa9d2fb );
        //colors[ImGuiCol_FrameBgActive]          = gui::hex2float_color( 0x3399ff );
        //colors[ImGuiCol_TitleBg]                = ImVec4(0.04f, 0.04f, 0.04f, 1.00f);
        //colors[ImGuiCol_TitleBgActive]          = gui::hex2float_color( 0x0c1924 );
        //colors[ImGuiCol_TitleBgCollapsed]       = gui::hex2float_color( 0x0c1924 );;
        //colors[ImGuiCol_MenuBarBg]              = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
        //colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
        //colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
        //colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
        //colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
        //colors[ImGuiCol_CheckMark]              = gui::hex2float_color( 0x3399ff );
        //colors[ImGuiCol_SliderGrab]             = gui::hex2float_color( 0x0875e2 );
        //colors[ImGuiCol_SliderGrabActive]       = gui::hex2float_color( 0x67b1fc );

        //colors[ImGuiCol_Button]                 = gui::hex2float_color( 0x883db2 ); 
        //colors[ImGuiCol_ButtonHovered]          = gui::hex2float_color( 0x982cd5 ); 
        //colors[ImGuiCol_ButtonActive]           = gui::hex2float_color( 0x9f32dc );

        //colors[ImGuiCol_Header]                 = gui::hex2float_color( 0xa9d2fb );
        //colors[ImGuiCol_HeaderHovered]          = gui::hex2float_color( 0xa9d2fb );
        //colors[ImGuiCol_HeaderActive]           = gui::hex2float_color( 0x3399ff );
        //colors[ImGuiCol_Separator]              = colors[ImGuiCol_Border];
        //colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.10f, 0.40f, 0.75f, 0.78f);
        //colors[ImGuiCol_SeparatorActive]        = ImVec4(0.10f, 0.40f, 0.75f, 1.00f);
        //colors[ImGuiCol_ResizeGrip]             = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
        //colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
        //colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
        //colors[ImGuiCol_Tab]                    = ImLerp(colors[ImGuiCol_Header],       colors[ImGuiCol_TitleBgActive], 0.80f);
        //colors[ImGuiCol_TabHovered]             = colors[ImGuiCol_HeaderHovered];
        //colors[ImGuiCol_TabActive]              = ImLerp(colors[ImGuiCol_HeaderActive], colors[ImGuiCol_TitleBgActive], 0.60f);
        //colors[ImGuiCol_TabUnfocused]           = ImLerp(colors[ImGuiCol_Tab],          colors[ImGuiCol_TitleBg], 0.80f);
        //colors[ImGuiCol_TabUnfocusedActive]     = ImLerp(colors[ImGuiCol_TabActive],    colors[ImGuiCol_TitleBg], 0.40f);
        //colors[ImGuiCol_PlotLines]              = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
        //colors[ImGuiCol_PlotLinesHovered]       = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
        //colors[ImGuiCol_PlotHistogram]          = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
        //colors[ImGuiCol_PlotHistogramHovered]   = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
        //colors[ImGuiCol_TextSelectedBg]         = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
        //colors[ImGuiCol_DragDropTarget]         = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
        //colors[ImGuiCol_NavHighlight]           = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
        //colors[ImGuiCol_NavWindowingHighlight]  = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
        //colors[ImGuiCol_NavWindowingDimBg]      = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
        //colors[ImGuiCol_ModalWindowDimBg]       = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);
    }
}

static 
void glfw_error_callback2( int error, const char* description )
{
    //logs( "glfw error %d: %s\n", error, description );
}

gl_window* instance = nullptr;
gl_window::gl_window( const char* w_caption, int w_width, int w_height ) : width( w_width ), height( w_height ), caption( w_caption )
{
    instance = this;
}

gl_window* gl_window::i( )
{
    return instance;
}

void gl_window::create( )
{
    me_thread =  std::thread( run_thead, this );

    std::this_thread::sleep_for( 1000ms );
}

inline ImFont* add_font_from_data( const void* data, int const i_size, const char* f_name, float const f_size, const ImWchar* ranges = nullptr )
{
    auto font_cfg           = ImFontConfig( );
    font_cfg.OversampleH    = font_cfg.OversampleV = 1;
    font_cfg.PixelSnapH     = true;
    auto& io                = ImGui::GetIO( );
    // if ( font_cfg.Name[ 0 ] == '\0' )
    //     strcpy_s( font_cfg.Name, f_name );

    if ( font_cfg.SizePixels <= 0.0f )
        font_cfg.SizePixels = f_size;

    io.IniFilename = ""; //"xxx__xx";//aquivo de config
    return io.Fonts->AddFontFromMemoryCompressedTTF( data, i_size, font_cfg.SizePixels, &font_cfg, ranges );
}

std::vector<ImFont*> gl_window::get_fonts( ) const
{
    return fonts;
}

void cursor_position_callback( GLFWwindow* window, double xpos, double ypos );
void mouse_button_callback( GLFWwindow* window, int button, int action, int mods );

//bool bIsAnyWindowHovered( )
//{
//	return ImGui::IsAnyWindowHovered( );
//}
void gl_window::routine( )
{
    glfwSetErrorCallback( glfw_error_callback2 );

    if ( !glfwInit( ) )
    {
        status = 1;
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

    window = glfwCreateWindow( width, height, caption, nullptr, nullptr );

    if ( !window )
    {
        status = 2;
        //logs( "glfwCreateWindow fail" );
        return;
    }

    //SetLayeredWindowAttributes( h_wnd, 0xff77ff, 255, LWA_ALPHA );

    glfwSetWindowMonitor( window, nullptr, 100, 100, width, height, 0 );

    glfwMakeContextCurrent( window );

    glfwSwapInterval( 1 ); // Enable vsync

    glfwSetCursorPosCallback( window, cursor_position_callback );

    glfwSetMouseButtonCallback( window, mouse_button_callback );

    ImGui::CreateContext( );

    ImGui::custom_StyleColorsLight( );

    auto& style = ImGui::GetStyle( );

    style.FrameRounding         = 5.0f;
    style.WindowRounding        = 5.0f;
    style.WindowTitleAlign.x    = 0.5f;
    style.Alpha                 = 1.0f;

    //static ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };//http://fontello.com/

    //auto* font = add_font_from_data( soniano_compressed_data, soniano_compressed_size, "soniano_12.ttf, 12px", 12.0f );

    //fonts.push_back( font );

    //font = add_font_from_data( soniano_compressed_data, soniano_compressed_size, "soniano_16.ttf, 16px", 16.0f );

    //fonts.push_back( font );

    //font = add_font_from_data( fontello_compressed_data, fontello_compressed_size, "icon, 24px", 24.0f, icon_ranges );

    //fonts.push_back( font );

    //font = add_font_from_data( font_icon_compressed_data, font_icon_compressed_size, "icon, 15px", 15.0f, icon_ranges );

    //fonts.push_back( font );

    ImGui_ImplGlfw_InitForOpenGL( window, true );

    ImGui_ImplOpenGL3_Init( glsl_version );

    while ( !glfwWindowShouldClose( window ) )
    {
        if ( b_goodbye )
            break;

        const auto visible = glfwGetWindowAttrib( window, GLFW_VISIBLE );

        if ( visible )
        {
            glfwPollEvents( );

            ImGui_ImplOpenGL3_NewFrame( );

            ImGui_ImplGlfw_NewFrame( );

            ImGui::NewFrame( );

            if ( frame_controls )
                frame_controls( this );

            ImGui::Render( );


            int display_w, display_h;

            glfwGetFramebufferSize( window, &display_w, &display_h );

            glViewport( 0, 0, display_w, display_h );

            glClearColor( 0, 0, 0, 0 );

            glClear( GL_COLOR_BUFFER_BIT );

            ImGui_ImplOpenGL3_RenderDrawData( ImGui::GetDrawData( ) );

            glfwSwapBuffers( window );

            if ( !show_window )
                close( );
        }

        std::this_thread::sleep_for( 10ms );

    }

    ImGui_ImplOpenGL3_Shutdown( );

    ImGui_ImplGlfw_Shutdown( );

    ImGui::DestroyContext( );

    glfwDestroyWindow( window );

    glfwTerminate( );
}

void gl_window::goodbye( )
{
    b_goodbye = true;
}

void gl_window::close( ) const
{
    glfwSetWindowShouldClose( window, GLFW_TRUE );

    exit( 0 );
}

void gl_window::run_thead( gl_window* inst )
{
    inst->routine( );
}

void gl_window::set_frame_controls( t_frame f_controls )
{
    frame_controls = f_controls;
}

void gl_window::set_size( int w_width, int w_height )
{
    glfwSetWindowSize( window, w_width, w_height );

    width = w_width;

    height = w_height;
}

ImVec2 gl_window::get_size( ) const
{
    return { static_cast<float>( width ) - static_cast<int>( f_left ), static_cast<float>( height ) - static_cast<int>( f_top ) };
}

void gl_window::set_frame_pos( float w_left, float w_top )
{
    f_top = w_top;

    f_left = w_left;

    set_size( width + static_cast<int>( w_left ), height + static_cast<int>( w_top ) );
}

ImVec2 gl_window::get_frame_pos( ) const
{
    return { f_left, f_top };
}

void gl_window::center( ) const
{
    GLFWmonitor* monitor = glfwGetPrimaryMonitor( );

    const GLFWvidmode* mode = glfwGetVideoMode( monitor );

    const auto screen_cx = mode->width;

    const auto screen_cy = mode->height;

    const auto center_x = ( screen_cx / 2 ) - ( width / 2 );

    const auto center_y = ( screen_cy / 2 ) - ( height / 2 );

    glfwSetWindowPos( window, center_x, center_y );
}

static int x_click = 0;
static int y_click = 0;
static auto move_window = false;
static std::chrono::steady_clock::time_point last_time = {};

void cursor_position_callback( GLFWwindow* window, double xpos, double ypos )
{
    if ( move_window )
    {
        const auto now = std::chrono::high_resolution_clock::now( );

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>( now - last_time ).count( );

        if ( elapsed < 100 )
			return;

        int x, y, width, height;

        glfwGetWindowPos( window, &x, &y );

        glfwGetWindowSize( window, &width, &height );

        const int x_window = x + int( xpos ) - x_click;

        const int y_window = y + int( ypos ) - y_click;

        glfwSetWindowPos( window, x_window, y_window );
    }

}

void mouse_button_callback( GLFWwindow* window, int button, int action, int mods )
{
    if ( button == GLFW_MOUSE_BUTTON_LEFT && action == GLFW_PRESS )
    {
        double mouse_x, mouse_y;

        glfwGetCursorPos( window, &mouse_x, &mouse_y );

        const auto title_bar_height = instance->height;

        x_click = int( mouse_x );

        y_click = int( mouse_y );

        if ( !ImGui::IsAnyItemHovered( ) ) { 

            last_time = std::chrono::high_resolution_clock::now( );
            move_window = ( static_cast<float>( y_click ) >= instance->f_top && static_cast<float>( y_click ) <= ( instance->f_top + title_bar_height ) );
        }
    }
    else if ( button == GLFW_MOUSE_BUTTON_LEFT && action == GLFW_RELEASE )
    {
        move_window = false;
    }
}