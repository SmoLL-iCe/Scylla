#include "GuiContext.h"
#include "../Tools/Utils.h"

GuiContext::GuiContext( glWindow* pWindow ) : pWindowInstance( pWindow )
{
    scyllaCtx = std::make_unique<ScyllaContext>( );
    processesIcons = std::make_unique<IconList>( L".exe" );
    strOEP = std::string( 17, '\0' );
    strVA = std::string( 17, '\0' );
    strSize = std::string( 17, '\0' );
}

GuiContext::~GuiContext( ) = default;

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


        ImGui::AddTab( "Processes", PCHR( Target ), pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "Modules", PCHR( Sitemap ), pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "OEP & IAT", PCHR( Flask ), pWindowInstance->getFont( 1 ) );
        ImGui::AddTab( "Config", PCHR( Gear ), pWindowInstance->getFont( 1 ) );


        pWindowInstance->setFramePos( 0.f, 0.f );
        pWindowInstance->setSize( 700, 700 );
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
        //ImGui::NewLine( );
        //ImGui::SameLine( 100.f );
        //ImGui::LoadingIndicatorCircle( "#bLoading", 20, ImGui::GetStyleColorVec4( ImGuiCol_ButtonHovered ), ImGui::GetStyleColorVec4( ImGuiCol_Button ), 10, 5.f );
        //ImGui::BeginDisabled( true );



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

            DrawInputText( "OEP:", strOEP.data( ), strOEP.size( ) );
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            DrawInputText( "VA:", strVA.data( ), strVA.size( ) );
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            DrawInputText( "Size:", strSize.data( ), strSize.size( ) );

            ImGui::EndGroup( );

            /// Utils::uintPtrToHex(

            ImGui::SameLine( 210.f );
            ImGui::BeginGroup( );
            if ( ImGui::Button( "IAT AutoSearch", ImVec2( 120.f, 34.f ) ) ) {
                scyllaCtx->m_entrypoint = Utils::hexToUintPtr( strOEP );

                std::thread( [ & ]( )
                    {
                        scyllaCtx->iatAutosearchActionHandler( );
                    } ).detach( );
            }
            ImGui::Dummy( ImVec2( 0.f, 1.f ) );
            if ( ImGui::Button( "Get Imports", ImVec2( 120.f, 34.f ) ) )
            {
                scyllaCtx->m_entrypoint = Utils::hexToUintPtr( strOEP );
                scyllaCtx->m_addressIAT = Utils::hexToUintPtr( strVA );
                scyllaCtx->m_sizeIAT = static_cast<std::uint32_t>( Utils::hexToUintPtr( strSize ) );
                scyllaCtx->getImportsActionHandler( );
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
                std::thread( [ & ]( )
                    {
                        scyllaCtx->dumpActionHandler( );
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

        if ( ImGui::BeginChild( "##processInfo", ImVec2( pWindowInstance->getSize( ).x - 16.f, 70.f ), true ) )
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


        //ImGui::EndDisabled( );

        ImGui::End( );
    }


    static bool bOnce = true;

    if ( bOnce )
    {
        //  auto future = std::async( std::launch::async, &ScyllaContext::setProcessById, &scyllaCtx, GetCurrentProcessId( ) );
        std::thread( [ & ]( )
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