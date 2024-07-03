#include "GuiContext.h"
#include "../Tools/Utils.h"

GuiContext::GuiContext( glWindow* pWindow ) : m_pWindowInstance( pWindow )
{
    m_scyllaCtx = std::make_unique<ScyllaContext>( );
    m_processesIcons = std::make_unique<IconList>( L".exe" );
    m_strOEP = std::string( 17, '\0' );
    m_strVA = std::string( 17, '\0' );
    m_strSize = std::string( 17, '\0' );
}

GuiContext::~GuiContext( ) = default;

void GuiContext::getIatHexString( ) {

    size_t szSize = 16;
#ifdef _WIN64
    auto OEPstr = std::format( "{:016X}", m_scyllaCtx->m_uEntryPoint );

    auto VAstr = std::format( "{:016X}", m_scyllaCtx->m_uAddressIAT );
#else
    szSize = 8;
    auto OEPstr = std::format( "{:08X}", m_scyllaCtx->m_uEntryPoint );

    auto VAstr = std::format( "{:08X}", m_scyllaCtx->m_uAddressIAT );
#endif // _WIN64
    auto VASizeStr = std::format( "{:08X}", m_scyllaCtx->m_uSizeIAT );

    std::memcpy( m_strOEP.data( ), OEPstr.data( ), szSize );
    std::memcpy( m_strVA.data( ), VAstr.data( ), szSize );
    std::memcpy( m_strSize.data( ), VASizeStr.data( ), szSize );
}

void GuiContext::DisplayFilter( const std::string& filterTitle, std::string& outFilter, ImVec2 Size, bool bWithBeginChild ) {

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

void GuiContext::DrawIconFontStatus( ImVec2 incPos, float size, int index ) {

    const char8_t* icon = nullptr;
    ImVec4 cColor = {};
    switch ( index )
    {
    case 0:
    {
        icon = CircleCheck;
        cColor = ImGui::Hex2FloatColor( 0x42f596 );
        break;
    }
    case 1:
    {
        icon = CircleXMark;
        cColor = ImGui::Hex2FloatColor( 0xf5425d );
        break;
    }
    case 2:
    {
        icon = CircleWarn;
        cColor = ImGui::Hex2FloatColor( 0xf5e342 );
        break;
    }
    case 3:
    {
        icon = TriangleWarn;
        cColor = ImGui::Hex2FloatColor( 0xf5e342 );
        break;
    }
    default:
        break;
    }

    ImGui::PushStyleColor( ImGuiCol_Text, cColor );
    ImGui::PushFont( ImGui::GetIO( ).Fonts->Fonts[ 1 ] );
    //AddText( const ImFont * font, float font_size, const ImVec2 & pos, ImU32 col, const char* text_begin, const char* text_end, float wrap_width, const ImVec4 * cpu_fine_clip_rect )
    ImGui::GetCurrentWindow( )->DrawList->AddText( 
        nullptr, 
        size, 
        ImGui::GetCurrentWindow( )->DC.CursorPos + incPos,
        ImGui::ColorConvertFloat4ToU32( cColor ),
        PCHR( icon )
    );
    //ImGui::Text( PCHR( icon ) );

    ImGui::PopFont( );
    ImGui::PopStyleColor( );

    //ImGui::SameLine( );
}

void GuiContext::Render( ) {

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


        ImGui::AddTab( "Processes", PCHR( Target ), m_pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "Modules", PCHR( Sitemap ), m_pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "OEP & IAT", PCHR( Flask ), m_pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "Config", PCHR( Gear ), m_pWindowInstance->getFont( 1 ) );


        m_pWindowInstance->setFramePos( 0.f, 0.f );
        m_pWindowInstance->setSize( 700, 700 );
        m_pWindowInstance->center( );
    }

    ImGui::SetNextWindowPos( { 0, m_pWindowInstance->getFramePos( ).y } ); // ImGuiCond_FirstUseEver
    ImGui::SetNextWindowSize( m_pWindowInstance->getSize( ) );

    auto uWindowFlags = 0;
    uWindowFlags |= ImGuiWindowFlags_NoScrollbar;
    uWindowFlags |= ImGuiWindowFlags_NoScrollWithMouse;
    uWindowFlags |= ImGuiWindowFlags_NoMove;
    uWindowFlags |= ImGuiWindowFlags_NoResize;
    uWindowFlags |= ImGuiWindowFlags_NoCollapse;
    //uWindowFlags |= ImGuiWindowFlags_NoTitleBar;


    if ( ImGui::Begin( "ImScylla", nullptr, uWindowFlags ) )
    {
        auto vPos = ImGui::GetCurrentWindow( )->DC.CursorPos;
        if ( m_lockInterface )
        {
            //vPos = ImVec2( 0.f, 0.f );
            float fRadiusSize = 60.f;
            ImGui::LoadingIndicatorCircle( "#bLoading",
                vPos
                + ImVec2( ImGui::GetWindowWidth( ) / 2.f, ImGui::GetWindowHeight( ) / 2.f )
                + ImVec2( -( fRadiusSize + ImGui::GetStyle( ).WindowPadding.x ), -fRadiusSize ),
                fRadiusSize,
                ImGui::GetStyleColorVec4( ImGuiCol_ButtonHovered ),
                ImGui::GetStyleColorVec4( ImGuiCol_ButtonHovered ), 10, 5.f );
        }

        ImGui::BeginDisabled( m_lockInterface );

        ImGui::PushStyleVar( ImGuiStyleVar_ButtonTextAlign, ImVec2( 0.f, 0.56f ) );
        ImGui::DisplayTabs( m_pWindowInstance->getSize( ).x );
        ImGui::PopStyleVar( );

        if ( ImGui::BeginChild( "##tabs", ImVec2( m_pWindowInstance->getSize( ).x - 16.f, 400.f ), true,
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

        auto fWidthBlock = ( ( ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 3.f ) ) / 100.f * 50.f );
        if ( ImGui::BeginChild( "##importsIAT", ImVec2( fWidthBlock, 130.f ), true,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse ) )
        {
            ImGui::Text( "IAT Info:" );

            ImGui::Separator( );

            ImGui::Dummy( ImVec2( 0.f, 1.f ) );

            auto DrawInputText = [ & ]( const char* pText, char* pBuff, size_t szSize, ImGuiInputTextCallback callback = nullptr ) {
                ImGui::GetCurrentWindow( )->DrawList->AddText(
                    ImGui::GetCurrentWindow( )->DC.CursorPos + ImVec2( 0.f, 3.f ),
                    ImGui::GetColorU32( ImGuiCol_Text ), pText );
                ImGui::NewLine( );
                ImGui::SameLine( 40.f );
                ImGui::PushItemWidth( 140.f );
                ImGui::InputText( std::string( "##" + std::string( pText ) ).c_str( ), pBuff, szSize, ImGuiInputTextFlags_CallbackCharFilter,
                    [ ]( ImGuiInputTextCallbackData* data ) -> int
                    {
                        return ( data->EventChar != 0 && !std::isxdigit( data->EventChar ) );;
                    } );
                ImGui::PopItemWidth( );
                };



            ImGui::BeginGroup( );
            DrawInputText( "OEP:", m_strOEP.data( ), m_strOEP.size( ) );
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            DrawInputText( "VA:", m_strVA.data( ), m_strVA.size( ) );
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            DrawInputText( "Size:", m_strSize.data( ), m_strSize.size( ) );
            ImGui::EndGroup( );

            ImGui::SameLine( 210.f );
            ImGui::BeginGroup( );
            if ( ImGui::Button( "IAT AutoSearch", ImVec2( 120.f, 34.f ) ) ) {
                m_scyllaCtx->m_uEntryPoint = Utils::hexToUintPtr( m_strOEP );

                m_lockInterface = true;

                std::thread( [ & ]( )
                    {
                        m_scyllaCtx->iatAutosearchActionHandler( );

                        getIatHexString( );

                        m_lockInterface = false;

                    } ).detach( );
            }
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            if ( ImGui::Button( "Get Imports", ImVec2( 120.f, 34.f ) ) )
            {
                auto uEntryPoint = Utils::hexToUintPtr( m_strOEP );
                auto uAddressIAT = Utils::hexToUintPtr( m_strVA );
                auto uSizeIAT    = static_cast<std::uint32_t>( Utils::hexToUintPtr( m_strSize ) );

                if ( uAddressIAT != 0 && uSizeIAT != 0 ) {

                    m_scyllaCtx->m_uEntryPoint = uEntryPoint;
                    m_scyllaCtx->m_uAddressIAT = uAddressIAT;
                    m_scyllaCtx->m_uSizeIAT = uSizeIAT;

                    m_lockInterface = true;

                    std::thread( [ & ]( )
                        {
                            m_scyllaCtx->getImportsActionHandler( );

                            m_lockInterface = false;

                        } ).detach( );

                }


            }
            ImGui::EndGroup( );

            ImGui::EndChild( );
        }
        ImGui::SameLine( fWidthBlock + ImGui::GetStyle( ).WindowPadding.x * 2.f );
        if ( ImGui::BeginChild( "##importsDump",
            ImVec2( fWidthBlock, 130.f ),
            true,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse ) )
        {
            ImGui::Text( "Dump:" );

            ImGui::Separator( );
            ImGui::BeginGroup( );
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            if ( ImGui::Button( "Dump", ImVec2( -1.f, 23.f ) ) )
            {
                m_lockInterface = true;

                std::thread( [ & ]( )
                    {
                        m_scyllaCtx->dumpActionHandler( );

                        m_lockInterface = false;
                    } ).detach( );
            }
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            ImGui::Button( "PE Rebuild", ImVec2( -1.f, 23.f ) );
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            ImGui::Button( "Fix Dump", ImVec2( -1.f, 23.f ) );
            ImGui::EndGroup( );

            ImGui::EndChild( );
        }

        //if ( scyllaCtx->getImportsHandling( )->thunkCount( ) )
        //{
        //    ImGui::Text( "IAT: %llX, %lX", (uint64_t)( scyllaCtx->m_addressIAT ), scyllaCtx->m_sizeIAT );
        //    ImGui::Text( "thunkCount: %d, invalid %d, suspect %d",
        //        scyllaCtx->getImportsHandling( )->thunkCount( ),
        //        scyllaCtx->getImportsHandling( )->invalidThunkCount( ),
        //        scyllaCtx->getImportsHandling( )->suspectThunkCount( )
        //    );
        //}

        if ( ImGui::BeginChild( "##processInfo", ImVec2( m_pWindowInstance->getSize( ).x - 16.f, 70.f ), true ) )
        {
            std::string strProcess = ( m_currentProcess.PID != 0 ) ? std::format( "PID: {:04}, Name: {}",
                m_currentProcess.PID,
                Utils::wstrToStr( m_currentProcess.pFileName ) ) : "No process selected";

            ImGui::Text( strProcess.c_str( ) );

            if ( m_currentProcess.PID )
            {
                std::string strModule = ( m_currentModule.uModBase != 0 ) ? std::format( "Module: {}",
                    Utils::wstrToStr( m_currentModule.pModulePath ) ) : "No module selected";

                ImGui::Text( strModule.c_str( ) );
            }

            ImGui::EndChild( );
        }

        ImGui::EndDisabled( );

        ImGui::End( );
    }


    static bool bOnce = true;

    if ( bOnce )
    {
        //  auto future = std::async( std::launch::async, &ScyllaContext::setProcessById, &scyllaCtx, GetCurrentProcessId( ) );
        std::thread( [ & ]( )
            {
                //ProcessAccessHelp::getProcessModules( GetCurrentProcess( ), ProcessAccessHelp::vOwnModuleList );

                ////scyllaCtx->setProcessById( GetCurrentProcessId( ) );
                ////scyllaCtx->setProcessById( ProcessAccessHelp::getProcessByName( L"export64.exe" ) );
                //auto status = m_scyllaCtx->setProcessById( ProcessAccessHelp::getProcessByName( L"export32pk.exe" ) );

                //if ( status == 0 )
                //{
                //    m_scyllaCtx->setDefaultFolder( LR"(X:\_\testScy\)" );

                //    if ( !ProcessAccessHelp::vModuleList.empty( ) )
                //    {
                //        m_currentModule = ProcessAccessHelp::vModuleList[ 0 ];
                //    }

                //    m_scyllaCtx->getImportsActionHandler( );

                //    m_currentProcess = *m_scyllaCtx->getCurrentProcess( );

                //    ImGui::SetActiveTabIndex( 2 );
                //}

                //m_scyllaCtx->setKernelModule( true );
#ifdef _DEBUG
                m_scyllaCtx->setDefaultFolder( LR"(X:\_\testScy\)" );
#endif // _DEBUG

            } ).detach( );


            bOnce = false;
    }
}