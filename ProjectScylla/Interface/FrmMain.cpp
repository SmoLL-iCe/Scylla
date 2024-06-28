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
#include "IconList.h"
#include "../ScyllaConfig.hpp"

using namespace std::chrono_literals;


constexpr char8_t YinYang[ 4 ] = u8"\uf6ad";
constexpr char8_t Target[ 4 ] = u8"\uf601";
constexpr char8_t Sitemap[ 4 ] = u8"\uf0e8";
constexpr char8_t Flask[ 4 ] = u8"\uf0c3";
constexpr char8_t Search[ 4 ] = u8"\uf002";
constexpr char8_t Gear[ 4 ] = u8"\uf013";
#define PCHR( x ) reinterpret_cast<const char*>( x )

extern "C" __declspec( dllexport ) int MyFunc( long parm1 ) {
	return 0;
}

std::unique_ptr<ScyllaContext> scyllaCtx = std::make_unique<ScyllaContext>( );
std::unique_ptr<IconList> processesIcons = std::make_unique<IconList>( L".exe" );

Process currentProcess = {};
ModuleInfo currentModule = {};

static 
void DisplayFilter( const std::string& filterTitle, std::string& outFilter, ImVec2 Size, bool bWithBeginChild ) {

    float fHeight = ImGui::GetCurrentWindow()->DC.CursorPos.y;

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
    else
    {
        auto fDiff = ImGui::GetCurrentWindow( )->DC.CursorPos.y - fHeight;
        ImGui::GetCurrentWindow( )->DC.CursorPos.y += ( Size.y > fDiff ) ? ( Size.y - fDiff ) : 0.f;
    }
}

static 
void ProcessesTab( ) {


    float fInnerWidth = ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fInnerHeight = ImGui::GetWindowHeight( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fHeightFilter = 30.f;

    static std::string strFilter = "";

    DisplayFilter( "Search process name", strFilter, ImVec2( fInnerWidth, fHeightFilter ), false );


#ifdef WIN64

    static int archFilter = 0;

    ImGui::BeginGroup( );

    ImGui::RadioButton( "All", &archFilter, 0 );

    auto fFractionWidth = ( ImGui::GetWindowWidth( ) / 100.f );
    auto fRadioLeft = fFractionWidth * 30.f + ImGui::GetStyle( ).WindowPadding.x * 2.f;

    ImGui::SameLine( fRadioLeft );
    ImGui::RadioButton( "Only 64 bits", &archFilter, 1 );

    fRadioLeft += fFractionWidth * 30.f + ImGui::GetStyle( ).WindowPadding.x * 2.f;
    ImGui::SameLine( fRadioLeft );
    ImGui::RadioButton( "Only 32 bits", &archFilter, 2 );

    ImGui::EndGroup( ); 
    
    ImGui::Dummy( ImVec2( 0.f, 3.f ) );

    fHeightFilter += 30.f;

#endif

    ImGui::BeginChildList( __LINE__, fInnerWidth, fInnerHeight - fHeightFilter, [ fInnerWidth ]( )
        {
            const float fBtnWidth = ( fInnerWidth
                - ( ImGui::GetStyle( ).WindowPadding.x * 2.f ) 
                 - ( ImGui::GetCurrentWindow( )->ScrollbarSizes.x )
                );

            auto nItems = 0;

            static std::vector<Process> vProcessList{};


            //=========================================================

            static std::chrono::steady_clock::time_point lastTimePoint = {};

            const auto nowTimePoint = std::chrono::high_resolution_clock::now( );

            if ( nowTimePoint.time_since_epoch().count( ) > lastTimePoint.time_since_epoch( ).count( ) )
            {
				vProcessList.clear( );

                vProcessList = ProcessLister( ).getProcessListSnapshotNative( );

                lastTimePoint = nowTimePoint + 3s;
            }

            //=========================================================

            static std::chrono::steady_clock::time_point lastTimeUpIconsPoint = {};

            if ( nowTimePoint.time_since_epoch( ).count( ) > lastTimeUpIconsPoint.time_since_epoch( ).count( ) )
            {
                // update icons
                for ( const auto& _Process : vProcessList )
                    processesIcons->extractIcon( _Process.pModulePath );

                lastTimeUpIconsPoint = nowTimePoint + 10s;
            }

            //=========================================================

            auto lowerFilter = Utils::StrToLower( strFilter );

            for ( const auto& _Process : vProcessList )
            {
                ++nItems;

#ifdef WIN64
                if ( archFilter )
                {
                    if ( archFilter == 1 && _Process.archType != PROCESS_64 )
						continue;

					if ( archFilter == 2 && _Process.archType != PROCESS_32 )
						continue;
                }
#endif // WIN64

                const std::string strProcessName = Utils::wstrToStr( _Process.pFileName );

                const std::string lowerProcessName = Utils::StrToLower( strProcessName );

                if ( !strFilter.empty( ) && lowerProcessName.find( lowerFilter ) == std::string::npos )
                    continue;

                auto icon = processesIcons->getIcon( _Process.pModulePath );

                std::string archTypeStr = "";

                switch ( _Process.archType )
                {
                    case PROCESS_32:
						archTypeStr = "32 bits";
						break;
#ifdef WIN64
                    case PROCESS_64:
                        archTypeStr = "64 bits";
                        break;
#endif // WIN64
                    case PROCESS_UNKNOWN:
                        archTypeStr = "Unknown";
                        break;
                    case PROCESS_MISSING_RIGHTS:
						archTypeStr = "Missing rights";
						break;
					default:
						archTypeStr = "Unknown";
						break;
                }

                const auto strFmt = std::format( "\t{:04}\t{}\t{}", _Process.PID, strProcessName, archTypeStr );

                const bool isSelected = ( currentProcess.PID != 0 ) ? ( currentProcess.PID == _Process.PID ) : false;

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

                ImVec2 iconSize = ImVec2( 20.f, 20.f );

                ImGui::Image( icon.TextureID, iconSize );
                //ImGui::NewLine( );
                ImGui::SameLine( iconSize.x + 16.f );
                ImGui::PushStyleVar( ImGuiStyleVar_ButtonTextAlign, ImVec2( 0.f, 0.56f ) );
                if ( ImGui::Button( strFmt.c_str( ), { fBtnWidth - ( iconSize.x +  8.f ), 25.f } ) ) {

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

    float fHeightFilter = 30.f;

    static std::string strFilter = "";

    DisplayFilter( "Search module name", strFilter, ImVec2( fInnerWidth, fHeightFilter ), false );

    fHeightFilter += ( ImGui::GetStyle( ).WindowPadding.y );

    static ImTextureID dllIcon = nullptr;

    if ( !dllIcon )
    {
        IconList::ExtractIconFromExtension( L".dll", dllIcon );
	}

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

                const std::string strModuleName = Utils::wstrToStr( pModuleInfo.pModulePath );

                const std::string lowerModuleName = Utils::StrToLower( strModuleName );

                if ( !strFilter.empty( ) && lowerModuleName.find( lowerFilter ) == std::string::npos )
					continue;


                auto& vReaderModuleList = scyllaCtx->getApiReader( )->vModuleList;

                auto itReaderModule = std::find_if( vReaderModuleList.begin( ), vReaderModuleList.end( ), 
                    [ & ]( ModuleInfo& m_Module ) {
                        return m_Module.uModBase == pModuleInfo.uModBase;
                    }
                );

                const auto ApiListSize = ( itReaderModule != vReaderModuleList.end( ) ) ? itReaderModule->vApiList.size( ) : 0;

                const auto strFmt = std::format( "\t0x{:016X} {} - Exports ({})", pModuleInfo.uModBase, Utils::wstrToStr( pModuleInfo.getFilename( ) ), ApiListSize );

                const bool isSelected = ( currentModule.uModBase != 0 ) ? ( currentModule.uModBase == pModuleInfo.uModBase ) : false;

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

                ImVec2 iconSize = ImVec2( 20.f, 20.f );

                ImGui::Image( dllIcon, iconSize );

                ImGui::SameLine( iconSize.x + 16.f );
                ImGui::PushStyleVar( ImGuiStyleVar_ButtonTextAlign, ImVec2( 0.f, 0.56f ) );
                if ( ImGui::Button( strFmt.c_str( ), { fBtnWidth - ( iconSize.x + 8.f ), 25.f } ) ) {
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
        ImGui::EndChild( );
    }


    if ( ImGui::BeginChild( "IAT", ImVec2( fInnerWidth, fInnerHeight - 100.f ), true ) )
    { 
        for ( auto& [key, moduleThunk] : scyllaCtx->getImportsHandling( )->vModuleList )
        {
            std::string strModuleName = "";

            strModuleName = std::format( "{} {} ({}) FThunk: {:08X}", 
                ( ( !moduleThunk.isValid( ) ) ? "[Invalid]" : "[OK]" ), 
                Utils::wstrToStr( moduleThunk.pModuleName ), 
                moduleThunk.mpThunkList.size( ), 
                moduleThunk.uFirstThunk  );

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

                    strFuncName = std::format( "  {} RVA: {:08X} Ord: {:04X} Name: {}",
                        ( ( !importThunk.bValid ) ? "[Invalid]" : ( importThunk.bSuspect ? "[Suspect]" : "[OK]" ) ),
                        importThunk.uRVA,
                        importThunk.uOrdinal,
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
void ConfigTab( )
{
    float fInnerWidth = ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    float fInnerHeight = ImGui::GetWindowHeight( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f );

    auto fHeightFraction = ( ( fInnerHeight - ImGui::GetStyle( ).WindowPadding.x ) / 100.f );
    ImGui::BeginGroup( );
    float fWithBlock = ( ( fInnerWidth - ImGui::GetStyle( ).WindowPadding.x ) / 2.f );
    if ( ImGui::BeginChild( "##Config1", ImVec2( fWithBlock, ( fHeightFraction * 60.f ) ), true ) )
    {
        ImGui::Text( "IAT Rebuilder" );

        std::wstring wstrSecName = Config::IAT_SECTION_NAME;
        std::string strSecName = Utils::wstrToStr( wstrSecName );

        ImGui::PushItemWidth( ( fWithBlock / 3.f ) );
        ImGui::InputText( "Section Name", strSecName.data( ), 5 );
        ImGui::PopItemWidth( );


        wstrSecName = Utils::strToWstr( strSecName );

        wcscpy_s( Config::IAT_SECTION_NAME, wstrSecName.c_str( ) );

        ImGui::Checkbox( "Fix IAT and OEP", &Config::IAT_FIX_AND_OEP_FIX );

        ImGui::Checkbox( "Use OriginalFirstThunk", &Config::OriginalFirstThunk_SUPPORT );

        ImGui::Checkbox( "New IAT", &Config::CREATE_NEW_IAT_IN_SECTION );
        
        ImGui::BeginDisabled( true );
        ImGui::Checkbox( "Don't create a new section", &Config::DONT_CREATE_NEW_SECTION );
        ImGui::EndDisabled( );

        //ImGui::NewLine( );

        ImGui::Checkbox( "Scan for Direct Imports", &Config::SCAN_DIRECT_IMPORTS );
        ImGui::Checkbox( "Fix Direct Imports NORMAL", &Config::FIX_DIRECT_IMPORTS_NORMAL );
        ImGui::Checkbox( "Fix Direct Imports UNIVERSAL", &Config::FIX_DIRECT_IMPORTS_UNIVERSAL );

        ImGui::EndChild( );
    }
    ImGui::SameLine( fWithBlock + ImGui::GetStyle( ).WindowPadding.x );
    if ( ImGui::BeginChild( "##Config2", ImVec2( fWithBlock, ( fHeightFraction * 60.f ) ), true ) )
    {
        ImGui::Text( "PE Rebuilder" );

        ImGui::Checkbox( "Update header checksum", &Config::UPDATE_HEADER_CHECKSUM );

        ImGui::Checkbox( "Create backup", &Config::CREATE_BACKUP );

        ImGui::Checkbox( "Remove DOS header stub", &Config::REMOVE_DOS_HEADER_STUB );

        ImGui::EndChild( );
    }

    if ( ImGui::BeginChild( "##Config3", ImVec2( fWithBlock, ( fHeightFraction * 40.f ) ), true ) )
    {
        ImGui::Text( "Dll injection" );

        ImGui::Checkbox( "Unload DLL after injection", &Config::DLL_INJECTION_AUTO_UNLOAD );

        ImGui::EndChild( );
    }
    ImGui::SameLine( fWithBlock + ImGui::GetStyle( ).WindowPadding.x );
    if ( ImGui::BeginChild( "##Config4", ImVec2( fWithBlock, ( fHeightFraction * 40.f ) ), true ) )
    {
        ImGui::Text( "Misc" );

        ImGui::Checkbox( "Use PE header from disk", &Config::USE_PE_HEADER_FROM_DISK );

        ImGui::Checkbox( "Enable debug privilege", &Config::DEBUG_PRIVILEGE );

        ImGui::Checkbox( "Suspend process for dumping", &Config::SUSPEND_PROCESS_FOR_DUMPING );

        ImGui::Checkbox( "Use advanced IAT search", &Config::USE_ADVANCED_IAT_SEARCH );

        ImGui::Checkbox( "Read APIs always from disk (slower!)", &Config::APIS_ALWAYS_FROM_DISK );

        ImGui::EndChild( );
    }
    ImGui::EndGroup( );
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
        ImGui::AddTab( "Config", PCHR( Gear ), pWindowInstance->getFont( 1 ) );


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

        if ( ImGui::BeginChild( "##tabs", ImVec2( pWindowInstance->getSize( ).x - 16.f, 400.f ), true, 
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse ) )
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
                case 3:
                {
					ConfigTab( );
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
