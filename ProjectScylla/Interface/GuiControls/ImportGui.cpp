#include "../GuiContext.h"
#include "../../Tools/Utils.h"

bool GuiContext::SwapIatFunctionShow( ImportThunk* importThunk ) {

    const float fHeightFilter = 38.f;

    static std::string strSwapModuleFilter = "";

    DisplayFilter( "Search module name", strSwapModuleFilter, ImVec2(
        ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f ),
        fHeightFilter ), false );

    auto& vModuleList = scyllaCtx->getApiReader( )->vModuleList;

    auto itModule = std::find_if( vModuleList.begin( ), vModuleList.end( ), 
        [ & ]( ModuleInfo& m_Module ) {
			return m_Module.uModBase == uSelectedModuleImportBase;
		} );

    auto bValidSelected = itModule != vModuleList.end( );

    std::string strImportModule = ( bValidSelected ) ?
        std::format( "{}", Utils::wstrToStr( itModule->getFilename( ) ) ) :
        "No module selected";

    if ( ImGui::BeginCombo( "##importModules", strImportModule.c_str( ) ) )
    {
        std::string lowerSwapModuleFilter = Utils::StrToLower( strSwapModuleFilter );

        for ( size_t ix = 0; ix < vModuleList.size( ); ix++ )
        {
            auto& moduleInfo = vModuleList[ ix ];

            if ( !moduleInfo.vApiList.size( ) )
                continue;

            const std::string strModuleName = Utils::wstrToStr( moduleInfo.getFilename( ) );

            const std::string lowerModuleName = Utils::StrToLower( strModuleName );

            if ( !strSwapModuleFilter.empty( ) && lowerModuleName.find( lowerSwapModuleFilter ) == std::string::npos )
                continue;

            if ( ImGui::Selectable( strModuleName.c_str( ), uSelectedModuleImportBase == moduleInfo.uModBase ) )
            {
                uSelectedModuleImportBase = moduleInfo.uModBase;
            }

            if ( uSelectedModuleImportBase == moduleInfo.uModBase )
                ImGui::SetItemDefaultFocus( );
        }

        ImGui::EndCombo( );
    }

    if ( bValidSelected ) {
        ImGui::BeginChild( "##swapFunctionsName", ImVec2( 0.f, 200.f ), true );

        static std::string strSwapFunctionName = "";

        DisplayFilter( "Search function name", strSwapFunctionName, ImVec2(
            ImGui::GetWindowWidth( ) - ( ImGui::GetStyle( ).WindowPadding.x * 2.f ),
            fHeightFilter ), false );

        std::string lowerSwapFunctionName = Utils::StrToLower( strSwapFunctionName );

        for ( auto& apiInfo : itModule->vApiList )
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

            const std::string lowerFunctionName = Utils::StrToLower( strFunctionName );

            if ( !strSwapFunctionName.empty( ) && lowerFunctionName.find( lowerSwapFunctionName ) == std::string::npos )
                continue;

            bool isSelected = ( nSelectedImportKey == apiInfo->uRVA );

            if ( ImGui::Selectable( strFunctionName.c_str( ), isSelected ) )
            {
                nSelectedImportKey = apiInfo->uRVA;
            }

            if ( isSelected )
                ImGui::SetItemDefaultFocus( );
        }
        ImGui::EndChild( );

        if ( nSelectedImportKey != 0 )
        {
            if ( ImGui::Button( "Apply", ImVec2( -1.f, 20.f ) ) )
            {
                auto itApiInfo = std::find_if( itModule->vApiList.begin( ), itModule->vApiList.end( ),
                    [ & ]( ApiInfo* api ) {
                        return api->uRVA == nSelectedImportKey;
                    } );

                if ( itApiInfo != itModule->vApiList.end( ) )
                {
                    auto pApiInfo = *itApiInfo;

                    scyllaCtx->getImportsHandling( )->
                        setImport( importThunk, pApiInfo->pModule->getFilename( ),
                            pApiInfo->name, pApiInfo->uOrdinal, pApiInfo->uHint, true, pApiInfo->isForwarded );
                }

                uSelectedModuleImportBase = 0;
                nSelectedImportKey = 0;
                ImGui::CloseCurrentPopup( );
                return true;
            }
        }
    }

    return false;
}
 
bool GuiContext::IatTab( )
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

    if ( ImGui::BeginChild( "IAT", ImVec2( fInnerWidth, fInnerHeight - 100.f ), true, ImGuiWindowFlags_HorizontalScrollbar ) )
    { 
        int nModuleItems = -1;
        for ( auto& [key, moduleThunk] : scyllaCtx->getImportsHandling( )->vModuleList )
        {
            ++nModuleItems;
            std::string strModuleName = std::format( "\t  {} ({}) FThunk: {:08X}",
                Utils::wstrToStr( moduleThunk.pModuleName ), 
                moduleThunk.mpThunkList.size( ), 
                moduleThunk.uFirstThunk  );

            DrawIconFontStatus( { 20.f, -1.f }, 14.f, !moduleThunk.isValid( ) );

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

                static ImportThunk* pSelectedImport = nullptr;
                if ( ImGui::BeginPopup( "##popSelectImport" ) )
                {
                    if ( pSelectedImport )
                    {

                        if ( SwapIatFunctionShow( pSelectedImport ) ) { 

                        	pSelectedImport = nullptr;
							// list modified
							// close all containers
							ImGui::EndPopup( );
							ImGui::TreePop( );
							ImGui::EndChild( );
							return true;
                        }

                        //if ( ImGui::Button( "Close", { -1.f, 20.f } ) )
                        //{
                        //    pSelectedImport = nullptr;
                        //    ImGui::CloseCurrentPopup( );
                        //}

                    }
                    ImGui::EndPopup( );
                }

                if ( ImGui::BeginPopup( "##popSelectImportOptions" ) )
                {
                    if ( ImGui::MenuItem( "Ivalidade" ) )
                    {
                        scyllaCtx->getImportsHandling( )->invalidateImport( pSelectedImport );
                    }

                    if ( ImGui::MenuItem( "Cut Thunk" ) )
                    {
                        scyllaCtx->getImportsHandling( )->cutImport( pSelectedImport );
                        ImGui::EndPopup( );
                        break; // prevent crash
                    }

                    if ( ImGui::BeginMenu( "Change Thunk" ) )
                    {
                        if ( SwapIatFunctionShow( pSelectedImport ) )
                        {
                            pSelectedImport = nullptr;
                            // list modified
                            // close all containers
                            ImGui::EndMenu( );
                            ImGui::EndPopup( );
                            ImGui::TreePop( );
                            ImGui::EndChild( );
                            return true;
                        }

                        ImGui::EndMenu( );
                    }
                    ImGui::EndPopup( );
                }


                int nImportItems = -1;
                for ( auto& [RVA, importThunk] : moduleThunk.mpThunkList ) {

                    ++nImportItems;
                    std::string strFuncName = std::format( "\t\t\t RVA: {:08X} Ord: {:04X} Name: {}",
                        importThunk.uRVA,
                        importThunk.uOrdinal,
                        importThunk.name );

                    DrawIconFontStatus( { 20.f, -1.f }, 14.f, ( importThunk.bSuspect ) ? 3 : !importThunk.bValid );

                    ImGui::Text( strFuncName.c_str( ) );

                    auto clickPopSelectImport = [ & ]( ) {

                            pSelectedImport = &importThunk;
                            uSelectedModuleImportBase = 0;
                            nSelectedImportKey = 0;
                            if ( moduleThunk.isValid( ) )
                            {
                                auto& vModuleList = scyllaCtx->getApiReader( )->vModuleList;

                                auto itModule = std::find_if( vModuleList.begin( ), vModuleList.end( ),
                                    [ & ]( ModuleInfo& m_Module ) {

                                        std::wstring wstrModule = m_Module.getFilename( );

                                        return wstrModule.find( moduleThunk.pModuleName ) != std::string::npos;
                                    } );

                                if ( itModule != vModuleList.end( ) )
                                    uSelectedModuleImportBase = itModule->uModBase;
                            };
                        };

                    if ( ImGui::IsItemClicked( ImGuiMouseButton_Left ) )
                    {
                        clickPopSelectImport( );
                        ImGui::OpenPopup( "##popSelectImport" );
                    }
                    if ( ImGui::IsItemClicked( ImGuiMouseButton_Right ) )
                    {
                        clickPopSelectImport( );
                        ImGui::OpenPopup( "##popSelectImportOptions" );
                    }
                }

                ImGui::TreePop( );
            }
        }

        ImGui::EndChild( );
    }

    return true;
}
