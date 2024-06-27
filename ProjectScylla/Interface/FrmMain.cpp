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
#include "imgui_custom.h"

using namespace std::chrono_literals;


constexpr char8_t YinYang[ 4 ] = u8"\uf6ad";
constexpr char8_t Target[ 4 ] = u8"\uf601";
constexpr char8_t Sitemap[ 4 ] = u8"\uf0e8";
constexpr char8_t Flask[ 4 ] = u8"\uf0c3";
constexpr char8_t Search[ 4 ] = u8"\uf002";
#define PCHR( x ) reinterpret_cast<const char*>( x )

extern "C" __declspec( dllexport ) int MyFunc( long parm1 ) {
	return 0;
}

std::unique_ptr<ScyllaContext> scyllaCtx = std::make_unique<ScyllaContext>( );

Process currentProcess = {};
ModuleInfo currentModule = {};

static 
void DisplayFilter( const std::string& filterTitle, std::string& outFilter, ImVec2 Size, bool bWithBeginChild ) {

    if ( bWithBeginChild )
    {
        ImGui::BeginChild( "##filter", Size, true );
    }
    ImGui::BeginGroup( );
    {
        char pFilter[ 256 ] = { 0 };
        auto isEmpty = outFilter.empty( );

        if ( !isEmpty ) {
        	strcpy_s( pFilter, outFilter.c_str( ) );
        }

        auto xPadding = ( ImGui::GetStyle( ).WindowPadding.x * ( bWithBeginChild ? 2.f : 0.f ) );
        ImGui::PushItemWidth( Size.x - xPadding );
        ImGui::InputTextWithHint( "##InputFilter", filterTitle.c_str( ), pFilter, sizeof( pFilter ) );
        ImGui::PopItemWidth( );

        ImGui::SameLine( Size.x - xPadding - 22.f );
        ImGui::PushFont( ImGui::GetIO( ).Fonts->Fonts[ 1 ] );
        ImGui::SetWindowFontScale( 0.6f );
        ImGui::Text( PCHR( Search ) );
        ImGui::SetWindowFontScale( 1.f );
        ImGui::PopFont( );

        outFilter = pFilter;
    }
    ImGui::EndGroup( );

    if ( bWithBeginChild )
    {
		ImGui::EndChild( );
	}
}

static 
void ProcessesTab( ) {


    float fInnerWidth = ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fInnerHeight = ImGui::GetWindowHeight( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fHeightFilter = 38.f;

    static std::string strFilter = "";

    DisplayFilter( "Search process name", strFilter, ImVec2( fInnerWidth, fHeightFilter ), true );

    fHeightFilter += ( ImGui::GetStyle( ).WindowPadding.y );

    ImGui::BeginChildList( __LINE__, fInnerWidth, fInnerHeight - fHeightFilter, [ fInnerWidth ]( )
        {
            const float fBtnWidth = ( fInnerWidth
                - ( ImGui::GetStyle( ).WindowPadding.x * 2.f ) 
                 - ( ImGui::GetCurrentWindow( )->ScrollbarSizes.x )
                );

            auto nItems = 0;

            static std::vector<Process> vProcessList{};

            static std::chrono::steady_clock::time_point lastTimePoint = {};

            const auto nowTimePoint = std::chrono::high_resolution_clock::now( );

            if ( nowTimePoint.time_since_epoch().count( ) > lastTimePoint.time_since_epoch( ).count( ) )
            {
				vProcessList.clear( );

                vProcessList = ProcessLister( ).getProcessListSnapshotNative( );

                lastTimePoint = nowTimePoint + 3s;
            }


            auto lowerFilter = Utils::StrToLower( strFilter );

            for ( const auto& _Process : vProcessList )
            {
                ++nItems;

                std::string strProcessName = Utils::wstrToStr( _Process.pFileName );

                std::string lowerProcessName = Utils::StrToLower( strProcessName );

                if ( !strFilter.empty( ) && lowerProcessName.find( lowerFilter ) == std::string::npos )
                    continue;

                auto strFmt = std::format( "\t{:04}\t{}", _Process.PID, strProcessName );

                bool isSelected = ( currentProcess.PID != 0 ) ? ( currentProcess.PID == _Process.PID ) : false;

                if ( isSelected )
                {
                    for ( int32_t xx = 0; xx < 3; xx++ ) {
                        auto col = ImGui::GetStyleColorVec4( ImGuiCol_ButtonHovered + xx );

                        col.x += 0.6f;
                        col.y += 0.1f;
                        col.z += 0.1f;

                        ImGui::PushStyleColor( ImGuiCol_Button + xx, col );
                    }
                }
                ImGui::PushStyleVar( ImGuiStyleVar_ButtonTextAlign, ImVec2( 0.f, 0.56f ) );
                if ( ImGui::Button( strFmt.c_str( ), { fBtnWidth, 25.f } ) ) { 

                    static bool bWaitProcess = false;

                    if ( !bWaitProcess )
                    {
                        bWaitProcess = true;

                        std::thread( [ & ]( Process ProcessInfo )
                            {
                                ProcessAccessHelp::vModuleList.clear( );

                                scyllaCtx->getApiReader( )->mpApiList.clear( );
                                if ( scyllaCtx->getApiReader( )->mpModuleThunkList )
                                {
                                    scyllaCtx->getApiReader( )->mpModuleThunkList->clear( );
                                    scyllaCtx->getApiReader( )->mpModuleThunkList = nullptr;
                                }

                                scyllaCtx->getApiReader( )->vModuleList.clear( );

                                scyllaCtx->getImportsHandling( )->vModuleList.clear( );
                                scyllaCtx->getImportsHandling( )->mpModuleListNew.clear( );

                                if ( scyllaCtx->setProcessById( ProcessInfo.PID ) == 0 ) { 

                                    scyllaCtx->setDefaultFolder( LR"(X:\_\testScy\)" );

                                    if ( !ProcessAccessHelp::vModuleList.empty( ) )
                                    {
                                        currentModule = ProcessAccessHelp::vModuleList[ 0 ];
                                    }

                                    scyllaCtx->getImportsActionHandler( );

                                    currentProcess = ProcessInfo;

                                    ImGui::SetActiveTabIndex( 1 );
                                }

                                bWaitProcess = false;

                            }, _Process ).detach( );
                    }

                }
                ImGui::PopStyleVar( );
                if ( isSelected )
                ImGui::PopStyleColor( 3 );
            }

        } );
}

static 
bool ModulesTab( ) {

    if ( currentProcess.PID == 0 || 
        !ProcessAccessHelp::hProcess ||
        ProcessAccessHelp::hProcess == INVALID_HANDLE_VALUE )
    {
        ImGui::SetActiveTabIndex( 0 );
        return false;
    }

    std::vector<ModuleInfo> vModuleList{};

    ProcessAccessHelp::getProcessModules( ProcessAccessHelp::hProcess, vModuleList );

    if ( vModuleList.empty( ) )
    {
        ImGui::SetActiveTabIndex( 0 );
        return false;
    }

    float fInnerWidth = ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fInnerHeight = ImGui::GetWindowHeight( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fHeightFilter = 38.f;

    static std::string strFilter = "";

    DisplayFilter( "Search module name", strFilter, ImVec2( fInnerWidth, fHeightFilter ), false );

    fHeightFilter += ( ImGui::GetStyle( ).WindowPadding.y );


    ImGui::BeginChildList( __LINE__, fInnerWidth, fInnerHeight - fHeightFilter, [ fInnerWidth, &vModuleList ]( )
        {
            const float fBtnWidth = ( fInnerWidth
                - ( ImGui::GetStyle( ).WindowPadding.x * 2.f )
                - ( ImGui::GetCurrentWindow( )->ScrollbarSizes.x )
                );

            auto nItems = 0;

            auto lowerFilter = Utils::StrToLower( strFilter );

            for ( const auto& pModuleInfo : vModuleList )
            {
                ++nItems;

                std::string strModuleName = Utils::wstrToStr( pModuleInfo.pModulePath );

                std::string lowerModuleName = Utils::StrToLower( strModuleName );

                if ( !strFilter.empty( ) && lowerModuleName.find( lowerFilter ) == std::string::npos )
					continue;


                auto& vReaderModuleList = scyllaCtx->getApiReader( )->vModuleList;

                auto itReaderModule = std::find_if( vReaderModuleList.begin( ), vReaderModuleList.end( ), 
                    [ & ]( ModuleInfo& m_Module ) {
                        return m_Module.uModBase == pModuleInfo.uModBase;
                    }
                );

                auto ApiListSize = ( itReaderModule != vReaderModuleList.end( ) ) ? itReaderModule->vApiList.size( ) : 0;

                auto strFmt = std::format( "\t0x{:016X} {} - Exports ({})", pModuleInfo.uModBase, Utils::wstrToStr( pModuleInfo.getFilename( ) ), ApiListSize );

                bool isSelected = ( currentModule.uModBase != 0 ) ? ( currentModule.uModBase == pModuleInfo.uModBase ) : false;

                if ( isSelected )
                {
                    for ( int xx = 0; xx < 3; xx++ ) {
                        auto col = ImGui::GetStyleColorVec4( ImGuiCol_ButtonHovered + xx );

                        col.x += 0.6f;
                        col.y += 0.1f;
                        col.z += 0.1f;

                        ImGui::PushStyleColor( ImGuiCol_Button + xx, col );
                    }
                }
                ImGui::PushStyleVar( ImGuiStyleVar_ButtonTextAlign, ImVec2( 0.f, 0.56f ) );
                if ( ImGui::Button( strFmt.c_str( ), { fBtnWidth, 25.f } ) ) {
                    currentModule = pModuleInfo;

                    scyllaCtx->setTargetModule( currentModule.uModBase, currentModule.uModBaseSize, currentModule.pModulePath );

                    scyllaCtx->setDefaultFolder( LR"(X:\_\testScy\)" );

                    ImGui::SetActiveTabIndex( 2 );
                }
                ImGui::PopStyleVar( );
                if ( isSelected )
                    ImGui::PopStyleColor( 3 );
            }

        } );


    return true;
}

static 
bool IatTab( ) 
{
    if ( currentProcess.PID == 0 ||
        !ProcessAccessHelp::hProcess ||
        ProcessAccessHelp::hProcess == INVALID_HANDLE_VALUE )
    {
        ImGui::SetActiveTabIndex( 0 );
        return false;
    }

    if ( currentModule.uModBase == 0 )
    {
		ImGui::SetActiveTabIndex( 1 );
        return false;
	}

    float fInnerWidth = ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fInnerHeight = ImGui::GetWindowHeight( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    if ( ImGui::BeginChild( "##imports", ImVec2( fInnerWidth, 70.f ), true ) )
    {
        if ( scyllaCtx->getImportsHandling( )->thunkCount( ) )
        {
            ImGui::Text( "IAT: %llX, %lX", (uint64_t)( scyllaCtx->m_addressIAT ), scyllaCtx->m_sizeIAT );
            ImGui::Text( "thunkCount: %d, invalid %d, suspect %d",
                scyllaCtx->getImportsHandling( )->thunkCount( ),
                scyllaCtx->getImportsHandling( )->invalidThunkCount( ),
                scyllaCtx->getImportsHandling( )->suspectThunkCount( )
            );
        }
    }
    ImGui::EndChild( );


    if ( ImGui::BeginChild( "IAT", ImVec2( fInnerWidth, fInnerHeight - 100.f ), true ) )
    { 
        for ( auto& [key, moduleThunk] : scyllaCtx->getImportsHandling( )->vModuleList )
        {
            std::string strModuleName = "";

            strModuleName = std::format( "{} {} ({})", ( ( !moduleThunk.isValid( ) ) ? "[Invalid]" : "[OK]" ), Utils::wstrToStr( moduleThunk.pModuleName ), moduleThunk.mpThunkList.size( ) );

            if ( ImGui::TreeNode( strModuleName.c_str( ) ) )
            {
                if ( ImGui::BeginPopupContextItem( strModuleName.c_str( ) ) )
                {
                    if ( ImGui::MenuItem( "Ivalidade" ) )
                    {
                        scyllaCtx->getImportsHandling( )->invalidateModule( &moduleThunk );
                    }

                    if ( ImGui::MenuItem( "Cut Module" ) )
                    {
                        scyllaCtx->getImportsHandling( )->cutModule( &moduleThunk );
                        ImGui::EndPopup( );
                        ImGui::TreePop( );
                        break; // prevent crash

                    }

                    ImGui::EndPopup( );
                }

                for ( auto& [RVA, importThunk] : moduleThunk.mpThunkList )
                {
                    std::string strFuncName = "";

                    strFuncName = std::format( "  {} {}",
                        ( ( !importThunk.bValid ) ? "[Invalid]" : ( importThunk.bSuspect ? "[Suspect]" : "[OK]" ) ),
                        importThunk.name );

                    ImGui::Text( strFuncName.c_str( ) );

                    strFuncName += std::to_string( RVA );
                    if ( ImGui::BeginPopupContextItem( strFuncName.c_str( ) ) )
                    {
                        if ( ImGui::MenuItem( "Ivalidade" ) )
                        {
                            scyllaCtx->getImportsHandling( )->invalidateImport( &importThunk );
                        }

                        if ( ImGui::MenuItem( "Cut Thunk" ) )
                        {
                            scyllaCtx->getImportsHandling( )->cutImport( &importThunk );
                            ImGui::EndPopup( );
                            break; // prevent crash
                        }

                        if ( ImGui::BeginMenu( "Change Thunk" ) )
                        {

                            float fHeightFilter = 38.f;

                            static std::string strSwapModuleFilter = "";

                            DisplayFilter( "Search module name", strSwapModuleFilter, ImVec2(
                                ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f ), 
                                fHeightFilter ), false );

                            static size_t nSelectedImport = -1;

                            auto& vImportModule = scyllaCtx->getApiReader( )->vModuleList;

                            auto bValidSelected = ( nSelectedImport != -1 && vImportModule.size( ) > nSelectedImport );

                            std::string strImportModule = ( bValidSelected ) ?
                                std::format( "{}", Utils::wstrToStr( vImportModule[ nSelectedImport ].getFilename( ) ) ) :
                                "No module selected";

                            if ( ImGui::BeginCombo( "##importModules", strImportModule.c_str( ) ) )
                            {
                                std::string lowerSwapModuleFilter = Utils::StrToLower( strSwapModuleFilter );

                                for ( size_t ix = 0; ix < vImportModule.size( ); ix++ )
                                {
                                    auto& moduleInfo = vImportModule[ ix ];

                                    if ( !moduleInfo.vApiList.size( ) )
                                        continue;

                                    std::string strModuleName = Utils::wstrToStr( moduleInfo.getFilename( ) );

                                    std::string lowerModuleName = Utils::StrToLower( strModuleName );

                                    if ( !strSwapModuleFilter.empty( ) && lowerModuleName.find( lowerSwapModuleFilter ) == std::string::npos )
										continue;

                                    if ( ImGui::Selectable( strModuleName.c_str( ), nSelectedImport == ix ) )
                                    {
                                        nSelectedImport = ix;
                                    }

                                    if ( nSelectedImport == ix )
                                        ImGui::SetItemDefaultFocus( );
                                }

                                ImGui::EndCombo( );
                            }

                            if ( bValidSelected ) {
                                ImGui::BeginChild( "##swapFunctionsName", ImVec2( 0, 200 ), true );

                                static std::string strSwapFunctionName = "";

                                DisplayFilter( "Search function name", strSwapFunctionName, ImVec2(
                                    ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f ),
                                    fHeightFilter ), false );

                                std::string lowerSwapFunctionName = Utils::StrToLower( strSwapFunctionName );

                                auto& moduleInfo = vImportModule[ nSelectedImport ];

                                for ( auto& apiInfo : moduleInfo.vApiList )
                                {
                                    std::string strFunctionName = "";

                                    if ( apiInfo->name[ 0 ] != '\0' )
                                    {
                                        strFunctionName = apiInfo->name;
                                    }
                                    else
                                    {
                                        char buf[ 6 ];
                                        sprintf_s( buf, "#%04X", apiInfo->uOrdinal );
                                        strFunctionName = buf;
                                    }

                                    std::string lowerFunctionName = Utils::StrToLower( strFunctionName );

                                    if ( !strSwapFunctionName.empty( ) && lowerFunctionName.find( lowerSwapFunctionName ) == std::string::npos )
										continue;


                                    if ( ImGui::MenuItem( strFunctionName.c_str( ) ) ) {
                                        scyllaCtx->getImportsHandling( )->
                                            setImport( &importThunk, apiInfo->pModule->getFilename( ),
                                                apiInfo->name, apiInfo->uOrdinal, apiInfo->uHint, true, apiInfo->isForwarded );

                                        // list modified
                                        // close all containers
                                        ImGui::EndChild( );
                                        ImGui::EndMenu( );
                                        ImGui::EndPopup( );
                                        ImGui::TreePop( );
                                        ImGui::EndChild( );
                                        return true;
                                    }
                                }

                                ImGui::EndChild( );
                            }

                            ImGui::EndMenu( );
                        }

                        ImGui::EndPopup( );
                    }

                }

                ImGui::TreePop( );
            }
        }


    
        ImGui::EndChild( );
    }



    if ( ImGui::Button( "Dump" ) )
    {

        std::thread( [ & ]( )
            {
                scyllaCtx->iatAutosearchActionHandler( );
                scyllaCtx->getImportsActionHandler( );

                scyllaCtx->dumpActionHandler( );
            } ).detach( );

    }

    
    return true;
}


static 
void FrameControls( glWindow* pWindowInstance )
{
    static ImGuiWindow* window = nullptr;
    static auto once = true;
    static auto blur_on = false;

    if ( once )
    {
        blur_on = true;
        once = false;


        ImGui::IniTabConfig( 0.f, 50.f, 1, 8.f, 2.f, 10.f );

        // https://fontawesome.com/versions

        // https://fontawesome.com/v6/search?o=r&m=free


        ImGui::AddTab( "Processes", PCHR( Target ), pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "Modules", PCHR( Sitemap ), pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "OEP & IAT", PCHR( Flask ), pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "Config", PCHR( Flask ), pWindowInstance->getFont( 1 ) );


        pWindowInstance->setFramePos( 0.f, 0.f );
        pWindowInstance->setSize( 600, 670 );
        pWindowInstance->center( );
    }

    ImGui::SetNextWindowPos( { 0, pWindowInstance->getFramePos( ).y } ); // ImGuiCond_FirstUseEver
    ImGui::SetNextWindowSize( pWindowInstance->getSize( ) );

    auto window_flags = 0;
    window_flags |= ImGuiWindowFlags_NoScrollbar;
    window_flags |= ImGuiWindowFlags_NoScrollWithMouse;
    window_flags |= ImGuiWindowFlags_NoMove;
    window_flags |= ImGuiWindowFlags_NoResize;
    window_flags |= ImGuiWindowFlags_NoCollapse;
    //window_flags |= ImGuiWindowFlags_NoTitleBar;

    if ( ImGui::Begin( "aaah", nullptr, window_flags ) )
    {

        ImGui::PushStyleVar( ImGuiStyleVar_ButtonTextAlign, ImVec2( 0.f, 0.56f ) );
        ImGui::DisplayTabs( pWindowInstance->getSize( ).x );
        ImGui::PopStyleVar( );

        if ( ImGui::BeginChild( "##process", ImVec2( pWindowInstance->getSize( ).x - 16.f, 400.f ), true ) )
        {
            while ( true )
            {

                switch ( ImGui::GetActiveTabIndex( ) )
                {
                case 0:
                {
                    ProcessesTab( );
                    break;
                }
                case 1:
                {
                    if ( !ModulesTab( ) )
                    {
                        continue;
                    }
                    break;
                }
                case 2:
                {
                    if ( !IatTab( ) )
                    {
						continue;
					}
                    break;
                }
                default:
                    break;
                }

                break;
            }

            ImGui::EndChild( );
        }

        if ( ImGui::BeginChild( "##processInfo", ImVec2( pWindowInstance->getSize( ).x - 16.f, 100.f ), true ) )
        {
            std::string strProcess = ( currentProcess.PID != 0 ) ? std::format( "PID: {:04}, Name: {}", 
                currentProcess.PID,
                Utils::wstrToStr( currentProcess.pFileName ) ) : "No process selected";

            ImGui::Text( strProcess.c_str( ) );

            if ( currentProcess.PID )
            {
                std::string strModule = ( currentModule.uModBase != 0 ) ? std::format( "Module: {}",
                    Utils::wstrToStr( currentModule.pModulePath ) ) : "No module selected";

                ImGui::Text( strModule.c_str( ) );
            }

            ImGui::EndChild( );
        }

        ImGui::End( );
    }


    static bool bOnce = true;

    if ( bOnce )
    {
        //  auto future = std::async( std::launch::async, &ScyllaContext::setProcessById, &scyllaCtx, GetCurrentProcessId( ) );
        std::thread( [&]( )
            {
                ProcessAccessHelp::getProcessModules( GetCurrentProcess( ), ProcessAccessHelp::vOwnModuleList );

                //scyllaCtx->setProcessById( GetCurrentProcessId( ) );
                //scyllaCtx->setProcessById( ProcessAccessHelp::getProcessByName( L"export64.exe" ) );
                auto status = scyllaCtx->setProcessById( ProcessAccessHelp::getProcessByName( L"export32pk.exe" ) );

                if ( status == 0 )
                {
                    scyllaCtx->setDefaultFolder( LR"(X:\_\testScy\)" );

                    if ( !ProcessAccessHelp::vModuleList.empty( ) )
                    {
                        currentModule = ProcessAccessHelp::vModuleList[ 0 ];
                    }

                    scyllaCtx->getImportsActionHandler( );

                    currentProcess = *scyllaCtx->getCurrentProcess( );

                    ImGui::SetActiveTabIndex( 2 );
                }

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
