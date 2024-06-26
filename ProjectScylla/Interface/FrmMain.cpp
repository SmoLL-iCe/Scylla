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

extern "C" __declspec( dllexport ) int MyFunc( long parm1 ) {
	return 0;
}

static 
void FrameControls( glWindow* instance )
{
    static ImGuiWindow* window = nullptr;
    static auto once = true;
    static auto blur_on = false;

    if ( once )
    {
        blur_on = true;
        once = false;


        instance->setFramePos( 0.f, 0.f );
        instance->setSize( 600, 670 );
        instance->center( );
    }

    ImGui::SetNextWindowPos( { 0, instance->getFramePos( ).y } ); // ImGuiCond_FirstUseEver
    ImGui::SetNextWindowSize( instance->getSize( ) );

    auto window_flags = 0;
    window_flags |= ImGuiWindowFlags_NoScrollbar;
    window_flags |= ImGuiWindowFlags_NoScrollWithMouse;
    window_flags |= ImGuiWindowFlags_NoMove;
    window_flags |= ImGuiWindowFlags_NoResize;
    window_flags |= ImGuiWindowFlags_NoCollapse;
    //window_flags |= ImGuiWindowFlags_NoTitleBar;

    auto wcharToString = [ ]( const wchar_t* wchar ) -> std::string
        {
            std::wstring wstr( wchar );
            return std::string( wstr.begin( ), wstr.end( ) );
        };


    static Process currentProcess = {};
    static ScyllaContext scyllaCtx = {};
    static ModuleInfo currentModule = {};


    if ( ImGui::Begin( "aaah", nullptr, window_flags ) )
    {
        if ( ImGui::BeginChild( "##process", ImVec2( instance->getSize( ).x - 16.f, 50.f ), true ) )
        {
            std::string strProcess = ( currentProcess.PID != 0 ) ? std::format( "{:04}\t{}", currentProcess.PID, wcharToString( currentProcess.pFileName ) ) : "No process selected";

            ImGui::PushItemWidth( instance->getSize( ).x - 32.f );
            if ( ImGui::BeginCombo( "##cbProcess", strProcess.c_str( ) ) )
            {
                ProcessLister processLister {};

                std::vector<Process>& vProcessList = processLister.getProcessListSnapshotNative( );

                for ( std::vector<Process>::iterator it = vProcessList.begin( ); it != vProcessList.end( ); ++it )
                {
                    auto strFmt = std::format( "{:04}\t{}", it->PID, wcharToString( it->pFileName ) );

                    bool is_selected = ( currentProcess.PID != 0 ) ? ( currentProcess.PID == it->PID ) : false;

                    if ( ImGui::Selectable( strFmt.c_str( ), is_selected ) )
                    {
                        currentProcess = *( &( *it ) );

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

            std::vector<ModuleInfo> vModuleList {};

            ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, vModuleList );

            if ( !vModuleList.empty( ) )
            {
                std::string strModule = ( currentModule.uModBase != 0 ) ? std::format( "{}",
                    wcharToString( currentModule.getFilename( ) ) ) : "No module selected";

                ImGui::PushItemWidth( instance->getSize( ).x - 32.f );
                if ( ImGui::BeginCombo( "##cbModules", strModule.c_str( ) ) )
                {
                    for ( auto& pModuleInfo : vModuleList )
                    {
                        auto& vReaderModuleList = scyllaCtx.getApiReader( )->vModuleList;

                        auto itReaderModule  = std::find_if( vReaderModuleList.begin( ), vReaderModuleList.end( ), [&] ( ModuleInfo& m_Module ) { 
                            return m_Module.uModBase == pModuleInfo.uModBase; 
                            } 
                        );

                        auto ApiListSize = ( itReaderModule != vReaderModuleList.end( ) ) ? itReaderModule->vApiList.size( ) : 0;

                        auto strFmt = std::format( "{} - ({})", wcharToString( pModuleInfo.getFilename( ) ), ApiListSize );

                        bool is_selected = ( currentModule.uModBase != 0 ) ? ( currentModule.uModBase == pModuleInfo.uModBase ) : false;

                        if ( ImGui::Selectable( strFmt.c_str( ), is_selected ) )
                        {
                            currentModule = pModuleInfo;

                            scyllaCtx.setTargetModule( currentModule.uModBase, currentModule.uModBaseSize, currentModule.pModulePath );
                        }

                        if ( is_selected )
                            ImGui::SetItemDefaultFocus( );
                    }

                    ImGui::EndCombo( );
                }
                ImGui::PopItemWidth( );










                //for ( auto& pModuleInfo : vModuleList )
                //{
                //    if ( std::wstring( pModuleInfo.pModulePath ).find( strModuleName ) != std::wstring::npos )
                //    {
                //        return setTargetModule( pModuleInfo.uModBase, pModuleInfo.uModBaseSize, pModuleInfo.pModulePath );
                //    }
                //}
            }

            if ( ImGui::Button( "Dump" ) )
            {

                std::thread( [&]( )
                    {
                        scyllaCtx.setDefaultFolder( LR"(X:\_\testScy\)" );
                        //scyllaCtx.iatAutosearchActionHandler( );
                        scyllaCtx.getImportsActionHandler( );

                        scyllaCtx.dumpActionHandler( );
                    } ).detach( );

            }
            if ( ImGui::BeginChild( "##imports", ImVec2( instance->getSize( ).x - 16.f, 500.f ), true ) )
            {
                if ( scyllaCtx.getImportsHandling( )->thunkCount( ) )
                {
                    ImGui::Text( "IAT: %llX, %lX", (uint64_t)scyllaCtx.m_addressIAT, scyllaCtx.m_sizeIAT );
                    ImGui::NewLine( );
                    ImGui::Text( "thunkCount: %d, invalid %d, suspect %d",
                        scyllaCtx.getImportsHandling( )->thunkCount( ),
                        scyllaCtx.getImportsHandling( )->invalidThunkCount( ),
                        scyllaCtx.getImportsHandling( )->suspectThunkCount( )
                    );
                    ImGui::NewLine( );

                    for ( auto& [key, moduleThunk] : scyllaCtx.getImportsHandling( )->vModuleList )
                    {
                        std::string strModuleName = "";


                        //if ( !moduleThunk.isValid( ) )
                        //    continue;

                        strModuleName = std::format( "{} {} ({})", ( ( !moduleThunk.isValid( ) ) ? "[Invalid]" : "[OK]" ), Utils::wstrToStr( moduleThunk.pModuleName ), moduleThunk.mpThunkList.size( ) );

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

                            for ( auto& [RVA, importThunk] : moduleThunk.mpThunkList )
                            {
                                std::string strFuncName = "";

                                //if ( !importThunk.valid )
                                //    continue;

                                strFuncName = std::format( "  {} {}",
                                    ( ( !importThunk.bValid ) ? "[Invalid]" : ( importThunk.bSuspect ? "[Suspect]" : "[OK]" ) ),
                                    importThunk.name );

                                ImGui::Text( strFuncName.c_str( ) );

                                if ( ImGui::BeginPopupContextItem( strFuncName.c_str( ) ) )
                                {
                                    if ( ImGui::MenuItem( "Ivalidade" ) )
                                    {
                                        printf( "Option 1 %s\n", strFuncName.c_str( ) );

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
            ImGui::EndChild( );

        }


        // ======================================================================================================


        ImGui::End( );
    }


    static bool bOnce = true;

    if ( bOnce )
    {
        //  auto future = std::async( std::launch::async, &ScyllaContext::setProcessById, &scyllaCtx, GetCurrentProcessId( ) );
        std::thread( [&]( )
            {

                ProcessAccessHelp::getProcessModules( GetCurrentProcess( ), ProcessAccessHelp::vOwnModuleList );

                //scyllaCtx.setProcessById( GetCurrentProcessId( ) );
                //scyllaCtx.setProcessById( ProcessAccessHelp::getProcessByName( L"export64.exe" ) );
                scyllaCtx.setProcessById( ProcessAccessHelp::getProcessByName( L"export32.exe" ) );
                scyllaCtx.setDefaultFolder( LR"(X:\_\testScy\)" );

            } ).detach( );


        bOnce = false;
    }
}

glWindow* window = nullptr;

void Interface::Initialize( )
{
    window = new glWindow( "", 10, 10 );

    window->create( );

    window->setFrameControls( FrameControls );

    std::this_thread::sleep_for( 100ms );

    window->center( );

    while ( true )
    {
        std::this_thread::sleep_for( 100ms );
    }
}
