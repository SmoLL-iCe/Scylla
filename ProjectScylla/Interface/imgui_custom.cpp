
#include "imgui_custom.h"

std::vector<float> vAlphas;
void ImGui::PushDisabled( const bool disabled )
{
	vAlphas.push_back( GetStyle( ).Alpha );
	GetStyle( ).Alpha = disabled ? 0.25f : 1.0f;
}

void ImGui::PopDisabled( int num )
{
	while ( num-- )
	{
		GetStyle( ).Alpha = vAlphas.back( );
		vAlphas.pop_back( );
	}
}

void ImGui::SeparatorEx2( ImVec2 padding, ImU32 col, float thickness )
{
	ImGuiWindow* window = GetCurrentWindow( );
	if ( window->SkipItems )
		return;
	ImGuiContext& g = *GImGui;

	float thickness_layout = 0.0f;

	float x1 = window->Pos.x;
	float x2 = window->Pos.x + window->Size.x;
	if ( g.GroupStack.Size > 0 && g.GroupStack.back( ).WindowID == window->ID )
		x1 += window->DC.Indent.x;

	if ( ImGuiTable* table = g.CurrentTable )
	{
		x1 = table->Columns[ table->CurrentColumn ].MinX;
		x2 = table->Columns[ table->CurrentColumn ].MaxX;
	}

	ImRect bb( ImVec2( x1 + padding.x, window->DC.CursorPos.y + padding.y ), ImVec2( x2 - padding.x, window->DC.CursorPos.y + padding.y + thickness ) );

	ItemSize( ImVec2( x2 - x1, thickness + padding.y + padding.y ) );
	const bool item_visible = ItemAdd( bb, 0 );
	if ( item_visible )
	{
		window->DrawList->AddLine( bb.Min, ImVec2( bb.Max.x, bb.Min.y ), col );
	}
}

bool ImGui::ButtonColor( const char* label, const ImVec4& col, const ImVec2& size_arg )
{
	auto mbo = false;
	auto cold = col;
	PushStyleColor( ImGuiCol_Button, cold );
	cold.y = col.y + 0.1f;
	cold.x = col.x + 0.1f;
	PushStyleColor( ImGuiCol_ButtonHovered, cold );
	cold.y = col.y + 0.2f;
	cold.x = col.x + 0.2f;
	PushStyleColor( ImGuiCol_ButtonActive, cold );
	mbo = Button( label, size_arg );
	PopStyleColor( 3 );
	return mbo;
}

struct sTabs
{
	std::string strText = "";
	std::string strIcon = "";
	ImFont* pFont = nullptr;
};

int nCurrentTabOpen = 0;

sTabs CurrentTab = { "" , "" , nullptr };

int ImGui::GetActiveTabIndex( )
{
	return nCurrentTabOpen;
}

void ImGui::SetActiveTabIndex( int index ) {
	nCurrentTabOpen = index;
}

static sTabs GetActiveTab( )
{
	return CurrentTab;
}

float fBtnSpacing		= 2.f;//90;
float fBtnRounding		= 2.f;//90;
float fBtnPaddingHoz    = 0.f;//90;
float fBtnHeight        = 20.f;
float fBtnIconLeft		= 0.f;
size_t szTabLines = 0;

void ImGui::IniTabConfig( 
	const float fPaddingHoz, 
	const float fTabHeight, 
	int TabLines, 
	const float fDistance, 
	const float fRounding, const float fButtonIconLeft )
{
	fBtnSpacing			= fDistance;
	fBtnRounding		= fRounding;
	fBtnPaddingHoz      = fPaddingHoz;
	fBtnHeight          = fTabHeight;
	szTabLines          = TabLines;
	fBtnIconLeft		= fButtonIconLeft;
}

std::vector<sTabs> vTabItems = {};

void ImGui::AddTab( const char* pText, const char* pIcon, ImFont* pFont)
{
	vTabItems.push_back( { pText, pIcon, pFont } );

	if ( CurrentTab.strText.empty( ) )
		CurrentTab = { pText, pIcon, pFont };
}

bool ImGui::ButtonIcon( const char* icon_str, const char* label, ImFont* pFontIcon, const ImVec2& size_arg, float iconDistance, ImGuiButtonFlags flags )
{
	ImGuiWindow* window = GetCurrentWindow( );
	if ( window->SkipItems )
		return false;

	ImGuiContext& g = *GImGui;
	const ImGuiStyle& style = g.Style;
	const ImGuiID id = window->GetID( label );

	PushFont( pFontIcon );
	const ImVec2 iconSizeStr = CalcTextSize( icon_str, nullptr, true );
	PopFont( );

	const ImVec2 label_size = CalcTextSize( label, NULL, true ) + ImVec2( iconSizeStr.x + iconDistance, 0.f);

	const ImVec2 pos = window->DC.CursorPos;

	ImVec2 size = CalcItemSize( size_arg, label_size.x + style.FramePadding.x * 2.0f, label_size.y + style.FramePadding.y * 2.0f );

	ImRect bb( pos, pos + size );
	if ( !ItemAdd( bb, id ) )
		return false;

	if ( g.LastItemData.InFlags & ImGuiItemFlags_ButtonRepeat )
		flags |= ImGuiButtonFlags_Repeat;
	bool hovered, held;
	bool pressed = ButtonBehavior( bb, id, &hovered, &held, flags );

	// Render
	const ImU32 col = GetColorU32( ( held && hovered ) ? ImGuiCol_ButtonActive : hovered ? ImGuiCol_ButtonHovered : ImGuiCol_Button );
	RenderNavHighlight( bb, id );
	RenderFrame( bb.Min, bb.Max, col, true, style.FrameRounding );

	bb.Min.x += fBtnIconLeft;
	bb.Max.x += fBtnIconLeft;

	ImRect bb2( bb.Min + style.FramePadding, bb.Max - style.FramePadding );

	const ImVec2 lblIcon = ImVec2( label_size.x, iconSizeStr.y );

	PushFont( pFontIcon );

	RenderTextClipped( 
		bb2.Min,
		bb2.Max,
		icon_str, NULL, &lblIcon, style.ButtonTextAlign, &bb2 );

	PopFont( );

	bb.Min.x += iconSizeStr.x + iconDistance;
	bb.Max.x += iconSizeStr.x + iconDistance;

	RenderTextClipped( bb.Min + style.FramePadding, bb.Max - style.FramePadding, label, NULL, &label_size, style.ButtonTextAlign, &bb );

	return pressed;
}

void ImGui::DisplayTabs( float fWidth )
{
	auto* const style = &ImGui::GetStyle( );
	auto* const colors = style->Colors;

	//ImGui::NewLine( );
	PushStyleVar( ImGuiStyleVar_FrameRounding, fBtnRounding );
	PushStyleColor( ImGuiCol_ButtonHovered, colors[ ImGuiCol_TabHovered ] );			// Color on mouse hover in tab
	//PushStyleColor(ImGuiCol_ButtonActive,	colors[ImGuiCol_TabClick]);			// Color on click tab

	const float fInnerContent = fWidth - ((fBtnPaddingHoz * 2.f ) + ( style->WindowPadding.x * 2.f ) );

	auto szTotalTabs = vTabItems.size( );

	ImGuiWindow* window = ImGui::GetCurrentWindow( );

	auto BeforeCursorPos = window->DC.CursorPos;

	const float fInitX = window->DC.CursorPos.x;

	auto vCurrentPos = ImVec2( fInitX, window->DC.CursorPos.y );

	size_t szRemaingTabs = szTotalTabs % szTabLines;

	size_t szTabsPerLine = szTotalTabs / szTabLines;

	int nTabIndex = 0;

	for ( size_t l = 0;  l < szTabLines;  l++ )
	{
		size_t szTabsInThisLine  = szTabsPerLine + ( l < szRemaingTabs ? 1 : 0 );

		vCurrentPos.x        = fInitX + fBtnPaddingHoz;

		window->DC.CursorPos = vCurrentPos;

		const float fTotalSpaces = fBtnSpacing * static_cast<float>( szTabsInThisLine - 1 );

		const float fBtnWidth = ( fInnerContent - fTotalSpaces ) / static_cast<float>( szTabsInThisLine );

		for ( size_t i = 0; i < szTabsInThisLine; i++ )
		{
			auto& _Tab = vTabItems[ nTabIndex ];

			( nCurrentTabOpen == nTabIndex ) ?
				PushStyleColor( ImGuiCol_Button, colors[ ImGuiCol_TabActive ] )				// Color on tab open
				:
				PushStyleColor( ImGuiCol_Button, colors[ ImGuiCol_Tab ] );					// Color on tab closed

			PushID( nTabIndex * 77878 );

			if ( !_Tab.strIcon.empty( ) && _Tab.pFont )
			{
				if ( ButtonIcon( _Tab.strIcon.c_str( ), _Tab.strText.c_str( ), _Tab.pFont, { fBtnWidth, fBtnHeight }, 10.f, 0 ) )
				{
					CurrentTab      = _Tab;
					nCurrentTabOpen = nTabIndex;
				}
			}
			//else
			//{
			//	if ( Button( _Tab.pText, ImVec2( fBtnWidth, fBtnHeight ) ) )	// If tab clicked
			//	{
			//		CurrentTab	 = _Tab;
			//		nCurrentTabOpen = i;
			//	}
			//}

			PopID( );

			PopStyleColor( );

			vCurrentPos.x += fBtnWidth + fBtnSpacing;

			window->DC.CursorPos = vCurrentPos;

			++nTabIndex;
		}

		vCurrentPos.y += (fBtnHeight + fBtnSpacing ) * szTabLines;

	}

	PopStyleColor( 1 );
	PopStyleVar( );

	BeforeCursorPos.y += fBtnHeight + fBtnSpacing;

	window->DC.CursorPos = BeforeCursorPos;
}

void ImGui::ButtonRainbow( const char* lbl, int id, float fWidth, float fHeight, std::function<void( )> code )
{
	ImGui::PushID( __LINE__ + 1894 * id );
	ImGui::PushStyleColor( ImGuiCol_Button, static_cast<ImVec4>( ImColor::HSV( id * 0.05f, 0.6f, 0.6f ) ) );
	ImGui::PushStyleColor( ImGuiCol_ButtonHovered, static_cast<ImVec4>( ImColor::HSV( id * 0.05f, 0.7f, 0.7f ) ) );
	ImGui::PushStyleColor( ImGuiCol_ButtonActive, static_cast<ImVec4>( ImColor::HSV( id * 0.05f, 0.8f, 0.8f ) ) );
	if ( ImGui::Button( lbl, ImVec2( fWidth, fHeight ) ) )
	{
		code( );
	}
	ImGui::PopStyleColor( 3 );
	ImGui::PopID( );
}

void ImGui::BeginChildList( int id, float fWidth, float fHeight, std::function<void( )> code )
{
	ImGui::PushStyleVar( ImGuiStyleVar_WindowPadding, ImVec2( 8.0f, 8.0f ) );
	ImGui::PushStyleVar( ImGuiStyleVar_FrameRounding, 3.0f );
	ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2.0f, 1.0f ) );
	ImGui::PushStyleColor( ImGuiCol_ChildBg, ImVec4( 0.20f, 0.25f, 0.35f, 1.00f ) );
	ImGui::PushID( id + 1893 );
	if ( ImGui::BeginChild( "", ImVec2( fWidth, fHeight ), true, ImGuiWindowFlags_HorizontalScrollbar ) )
	{
		code( );

		ImGui::EndChild( );
	}
	ImGui::PopID( );
	ImGui::PopStyleColor( );
	ImGui::PopStyleVar( 3 );
}

ImVec4 ImGui::Hex2FloatColor( uint32_t hex_color, const float a )
{
	auto* const p_byte = reinterpret_cast<uint8_t*>( &hex_color );
	const auto r = static_cast<float>( static_cast<float>( p_byte[ 2 ] ) / 255.f );
	const auto g = static_cast<float>( static_cast<float>( p_byte[ 1 ] ) / 255.f );
	const auto b = static_cast<float>( static_cast<float>( p_byte[ 0 ] ) / 255.f );
	return { r, g, b, a };
}