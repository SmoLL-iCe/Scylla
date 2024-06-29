#pragma once
#include "Thirdparty/ImGui/imgui.h"
#include "Thirdparty/ImGui/imgui_internal.h"
#include <functional>


namespace ImGui
{
	void PushDisabled( const bool disabled = true );

	void PopDisabled( int num = 1 );

	void SeparatorEx2( ImVec2 padding = { 20.f, 8.f }, ImU32 col = 0x10FFFFFF, float thickness = 1.f );

	bool ButtonIcon( const char* icon_str, const char* label, ImFont* font_icon, const ImVec2& size_arg, float iconDistance, ImGuiButtonFlags flags );

	bool ButtonColor( const char* label, const ImVec4& col, const ImVec2& size_arg );

	int GetActiveTabIndex( );
	void SetActiveTabIndex( int index );

	void IniTabConfig( const float fPaddingHoz, const float fTabHeight, int TabLines, const float fDistance, const float fRounding, const float fButtonIconLeft );

	void AddTab( const char* pText, const char* pIcon = nullptr, ImFont* pFont = nullptr );

	void DisplayTabs( float fWidth );

	void ButtonRainbow( const char* lbl, int id, float fWidth, float fHeight, std::function<void( )> code );

	void BeginChildList( int id, float fWidth, float fHeight, std::function<void( )> code );

	ImVec4 Hex2FloatColor( uint32_t hex_color, const float a = 1.f );

	void LoadingIndicatorCircle( const char* label, const float indicator_radius,
		const ImVec4& main_color, const ImVec4& backdrop_color,
		const int circle_count, const float speed );
}