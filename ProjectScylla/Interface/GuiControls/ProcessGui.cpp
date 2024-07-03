#include "../GuiContext.h"
#include "../../Tools/Utils.h"

void GuiContext::ProcessesTab( ) {

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

    ImGui::BeginChildList( __LINE__, fInnerWidth, fInnerHeight - fHeightFilter, [ this, fInnerWidth ]( )
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
                    m_processesIcons->extractIcon( _Process.pModulePath );

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

                auto icon = m_processesIcons->getIcon( _Process.pModulePath );

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

                const bool isSelected = ( m_currentProcess.PID != 0 ) ? ( m_currentProcess.PID == _Process.PID ) : false;

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
                ImGui::SameLine( iconSize.x + 16.f );
                ImGui::PushStyleVar( ImGuiStyleVar_ButtonTextAlign, ImVec2( 0.f, 0.56f ) );
                if ( ImGui::Button( strFmt.c_str( ), { fBtnWidth - ( iconSize.x +  8.f ), 25.f } ) ) {

                    m_lockInterface = true;

                    std::thread( [ & ]( Process ProcessInfo )
                        {
                            ProcessAccessHelp::vModuleList.clear( );

                            m_scyllaCtx->getApiReader( )->mpApiList.clear( );
                            if ( m_scyllaCtx->getApiReader( )->mpModuleThunkList ) {

                                m_scyllaCtx->getApiReader( )->mpModuleThunkList->clear( );
                                m_scyllaCtx->getApiReader( )->mpModuleThunkList = nullptr;
                            }

                            m_scyllaCtx->getApiReader( )->vModuleList.clear( );

                            m_scyllaCtx->getImportsHandling( )->vModuleList.clear( );
                            m_scyllaCtx->getImportsHandling( )->mpModuleListNew.clear( );

                            if ( m_scyllaCtx->setProcessById( ProcessInfo.PID ) == 0 ) { 

                                getIatHexString( );

#ifdef _DEBUG
                                m_scyllaCtx->setDefaultFolder( LR"(X:\_\testScy\)" );
#endif // _DEBUG

                                if ( !ProcessAccessHelp::vModuleList.empty( ) )
                                {
                                    m_currentModule = ProcessAccessHelp::vModuleList[ 0 ];
                                }

                                m_scyllaCtx->getImportsActionHandler( );

                                m_currentProcess = ProcessInfo;

                                ImGui::SetActiveTabIndex( 1 );
                            }

                            m_lockInterface = false;

                        }, _Process ).detach( );
                }

                
                ImGui::PopStyleVar( );
                if ( isSelected )
                ImGui::PopStyleColor( 3 );
            }

        } );
}
