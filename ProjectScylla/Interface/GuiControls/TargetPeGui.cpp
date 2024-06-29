#include "../GuiContext.h"
#include "../../Tools/Utils.h"

bool GuiContext::ModulesTab( ) {

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

    ImGui::BeginChildList( __LINE__, fInnerWidth, fInnerHeight - fHeightFilter, [ this, fInnerWidth, &vModuleList ]( )
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

#ifdef _WIN64
                    auto OEPstr = std::format( "{:016X}", scyllaCtx->m_entrypoint );

                    auto VAstr = std::format( "{:016X}", scyllaCtx->m_addressIAT );
#else
                    auto OEPstr = std::format( "{:08X}", scyllaCtx->m_entrypoint );

                    auto VAstr = std::format( "{:08X}", scyllaCtx->m_addressIAT );
#endif // _WIN64
                    auto VASizeStr = std::format( "{:08X}", scyllaCtx->m_sizeIAT );

                    std::memcpy( strOEP.data( ), OEPstr.data( ), 16 );
                    std::memcpy( strVA.data( ), VAstr.data( ), 16 );
                    std::memcpy( strSize.data( ), VASizeStr.data( ), 16 );

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
