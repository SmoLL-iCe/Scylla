#include "FrmMain.h"
#include "Thirdparty/ImGui/imgui.h"
#include "Thirdparty/ImGui/imgui_internal.h"
#include <map>
#include <format>
#include "CreateWindow.h"
#include <chrono>
#include "../ProcessLister.h"
#include "../ScyllaContext.h"
#include "../Tools/Utils.h"
#include <future>
#include <chrono>
#include <coroutine>
#include <thread>

using namespace std::chrono_literals;

ImVec4 hex2float_color( uint32_t hex_color, const float a = 1.f )
{
    auto* const p_byte = reinterpret_cast<uint8_t*>( &hex_color );
    const auto r = static_cast<float>( static_cast<float>( p_byte[ 2 ] ) / 255.f );
    const auto g = static_cast<float>( static_cast<float>( p_byte[ 1 ] ) / 255.f );
    const auto b = static_cast<float>( static_cast<float>( p_byte[ 0 ] ) / 255.f );
    return { r, g, b, a };
}

void forms::main( )
{

}

void frame_controls( gl_window* instance )
{
    static ImGuiWindow* window = nullptr;
    static auto once = true;
    static auto blur_on = false;

    if ( once )
    {
        blur_on = true;
        once = false;


        instance->set_frame_pos( 0.f, 0.f );
        instance->set_size( 600, 670 );
        instance->center( );
    }

    ImGui::SetNextWindowPos( { 0, instance->get_frame_pos( ).y } ); // ImGuiCond_FirstUseEver
    ImGui::SetNextWindowSize( instance->get_size( ) );

    auto window_flags = 0;
    window_flags |= ImGuiWindowFlags_NoScrollbar;
    window_flags |= ImGuiWindowFlags_NoScrollWithMouse;
    window_flags |= ImGuiWindowFlags_NoMove;
    window_flags |= ImGuiWindowFlags_NoResize;
    window_flags |= ImGuiWindowFlags_NoCollapse;
    //window_flags |= ImGuiWindowFlags_NoTitleBar;

    auto wcharToString = []( const wchar_t* wchar ) -> std::string
	{
		std::wstring wstr( wchar );
		return std::string( wstr.begin( ), wstr.end( ) );
	};


    static Process currentProcess = {};
    static ScyllaContext scyllaCtx = {};
    static ModuleInfo currentModule = {};


    if ( ImGui::Begin( "aaah", nullptr, window_flags ) )
    {
        if ( ImGui::BeginChild( "##process", ImVec2( instance->get_size( ).x - 16.f, 50.f ), true ) )
        {
            std::string strProcess = ( currentProcess.PID != 0 ) ? std::format( "{:04}\t{}", currentProcess.PID, wcharToString( currentProcess.filename ) ) : "No process selected";

            ImGui::PushItemWidth( instance->get_size( ).x - 32.f );
            if ( ImGui::BeginCombo( "##cbProcess", strProcess.c_str( ) ) )
            {
                ProcessLister processLister{};

                std::vector<Process>& processList = processLister.getProcessListSnapshotNative( );

                for ( std::vector<Process>::iterator it = processList.begin( ); it != processList.end( ); ++it )
                {
                    auto strFmt = std::format( "{:04}\t{}", it->PID, wcharToString( it->filename ) );

                    bool is_selected = ( currentProcess.PID != 0 ) ? ( currentProcess.PID == it->PID ) : false;

                    if ( ImGui::Selectable( strFmt.c_str( ), is_selected ) )
                    {
                        currentProcess = *( &( *it ));

                        scyllaCtx.setProcessById( currentProcess.PID );

                        scyllaCtx.setDefaultFolder( LR"(X:\_\testScy\)" );
                    }

                    if ( is_selected )
                        ImGui::SetItemDefaultFocus( );
                }

                ImGui::EndCombo( );
            }
            ImGui::PopItemWidth( );

        }
        ImGui::EndChild( );


        if ( ProcessAccessHelp::hProcess && ProcessAccessHelp::hProcess != INVALID_HANDLE_VALUE ) {

            std::vector<ModuleInfo> moduleList{};

            ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, moduleList );

            if ( !moduleList.empty( ) )
            {
                std::string strModule = ( currentModule.modBaseAddr != 0 ) ? std::format( "{}",
                    wcharToString( currentModule.getFilename( ) ) ) : "No module selected";

                ImGui::PushItemWidth( instance->get_size( ).x - 32.f );
                if ( ImGui::BeginCombo( "##cbModules", strModule.c_str( ) ) )
                {
                    for ( auto& moduleInfo : moduleList )
                    {
                        auto strFmt = std::format( "{}", wcharToString( moduleInfo.getFilename( ) ) );

                        bool is_selected = ( currentModule.modBaseAddr != 0 ) ? ( currentModule.modBaseAddr == moduleInfo.modBaseAddr ) : false;

                        if ( ImGui::Selectable( strFmt.c_str( ), is_selected ) )
                        {
                            currentModule = moduleInfo;

                            scyllaCtx.setTargetModule( currentModule.modBaseAddr, currentModule.modBaseSize, currentModule.fullPath );
                        }

                        if ( is_selected )
                            ImGui::SetItemDefaultFocus( );
                    }

                    ImGui::EndCombo( );
                }
                ImGui::PopItemWidth( );










                //for ( auto& moduleInfo : moduleList )
                //{
                //    if ( std::wstring( moduleInfo.fullPath ).find( strModuleName ) != std::wstring::npos )
                //    {
                //        return setTargetModule( moduleInfo.modBaseAddr, moduleInfo.modBaseSize, moduleInfo.fullPath );
                //    }
                //}
            }
        
            if ( ImGui::Button( "Dump" ) )
            {

                std::thread( [ & ]( )
                    {
                        scyllaCtx.setDefaultFolder( LR"(X:\_\testScy\)" );
                        scyllaCtx.iatAutosearchActionHandler( );
                        scyllaCtx.getImportsActionHandler( );
					} ).detach( );


				//scyllaCtx.dumpActionHandler( );

			}

            if ( scyllaCtx.getImportsHandling( )->thunkCount( ) )
            {
                ImGui::Text( "IAT: %llX, %lX", scyllaCtx.m_addressIAT, scyllaCtx.m_sizeIAT );
                ImGui::NewLine( );
                ImGui::Text( "thunkCount: %d, invalid %d, suspect %d", 
                    scyllaCtx.getImportsHandling( )->thunkCount( ), 
                    scyllaCtx.getImportsHandling( )->invalidThunkCount(),
                    scyllaCtx.getImportsHandling( )->suspectThunkCount() 
                );
                ImGui::NewLine( );

                for ( auto& [key, moduleThunk] : scyllaCtx.getImportsHandling( )->moduleList )
                {
                    std::string strModuleName = "";

                    
                    //if ( !moduleThunk.isValid( ) )
                    //    continue;

                    strModuleName = std::format( "{} {} ({})", (( !moduleThunk.isValid( ) ) ? "[Invalid]" : "[OK]"), Utils::wstrToStr( moduleThunk.moduleName ), moduleThunk.thunkList.size( ) );

                    if ( ImGui::TreeNode( strModuleName.c_str( ) ) )
                    {
                        if ( ImGui::BeginPopupContextItem( strModuleName.c_str( ) ) )
                        {
                            if ( ImGui::MenuItem( "Ivalidade" ) )
                            {
								scyllaCtx.getImportsHandling( )->invalidateModule( &moduleThunk );

                            }


                            if ( ImGui::MenuItem( "Cut Module" ) )
                            {
                                scyllaCtx.getImportsHandling( )->cutModule( &moduleThunk );
                                ImGui::EndPopup( );
                                ImGui::TreePop( );
                                break; // prevent crash

                            }

                            ImGui::EndPopup( );
                        }

                        for ( auto& [rva, importThunk] : moduleThunk.thunkList )
                        {
                            std::string strFuncName = "";

                            //if ( !importThunk.valid )
                            //    continue;

                            strFuncName = std::format( "  {} {}",
                                ( ( !importThunk.valid ) ? "[Invalid]" : ( importThunk.suspect ? "[Suspect]" : "[OK]" ) ),
                                importThunk.name );

                            ImGui::Text( strFuncName.c_str( ) );

                            if ( ImGui::BeginPopupContextItem( strFuncName.c_str( ) ) )
                            {
                                if ( ImGui::MenuItem( "Ivalidade" ) )
                                {
                                    printf ( "Option 1 %s\n", strFuncName.c_str( ) );

                                    scyllaCtx.getImportsHandling( )->invalidateImport( &importThunk );
                                }
                                if ( ImGui::MenuItem( "Cut Thunk" ) )
                                {
                                    scyllaCtx.getImportsHandling( )->cutImport( &importThunk );
                                    ImGui::EndPopup( );
                                    break; // prevent crash
                                }
                                if ( ImGui::MenuItem( "Option 3" ) )
                                {
                                    // Handle Option 3
                                }
                                ImGui::EndPopup( );
                            }

                        }
                        ImGui::TreePop( );
                    }
                }
       


            }

        }


        // ======================================================================================================


        ImGui::End( );
    }


    static bool bOnce = true;

    if ( bOnce )
    {
        //scyllaCtx.setProcessById( 53496 );

        //  auto future = std::async( std::launch::async, &ScyllaContext::setProcessById, &scyllaCtx, GetCurrentProcessId( ) );
        std::thread( [ & ]( )
            {
                scyllaCtx.setProcessById( GetCurrentProcessId( ) );
                scyllaCtx.setDefaultFolder( LR"(X:\_\testScy\)" );

            } ).detach( );


        bOnce = false;
    }
}

gl_window* window = nullptr;
void gui_init( )
{
    window = new gl_window( "", 10, 10 );

    window->create( );

    window->set_frame_controls( frame_controls );

    std::this_thread::sleep_for( 100ms );

    window->center( );

    while ( true )
    {
        std::this_thread::sleep_for( 100ms );
    }
}
