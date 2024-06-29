#include "../GuiContext.h"
#include "../../ScyllaConfig.hpp"
#include "../../Tools/Utils.h"


void GuiContext::ConfigTab( )
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