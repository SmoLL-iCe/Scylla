#pragma once
#include <iostream>
#include <Windows.h>
#include <future>
#include <chrono>
#include <coroutine>
#include <thread>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <format>
#include "Thirdparty/ImGui/imgui.h"
#include "Thirdparty/ImGui/imgui_internal.h"
#include "CreateWindow.h"
#include "../ProcessLister.h"
#include "../ScyllaContext.h"
#include "imgui_custom.h"
#include "IconList.h"

using namespace std::chrono_literals;


constexpr char8_t YinYang[ 4 ] = u8"\uf6ad";
constexpr char8_t Target[ 4 ] = u8"\uf601";
constexpr char8_t Sitemap[ 4 ] = u8"\uf0e8";
constexpr char8_t Flask[ 4 ] = u8"\uf0c3";
constexpr char8_t Search[ 4 ] = u8"\uf002";
constexpr char8_t Gear[ 4 ] = u8"\uf013";
constexpr char8_t CircleCheck[ 4 ] = u8"\uf058";
constexpr char8_t CircleXMark[ 4 ] = u8"\uf057";
constexpr char8_t CircleWarn[ 4 ] = u8"\uf06a";
constexpr char8_t TriangleWarn[ 4 ] = u8"\uf071";
#define PCHR( x ) reinterpret_cast<const char*>( x )

class GuiContext
{
public:
	GuiContext( glWindow* pWindow );
	~GuiContext( );
	void Render( );
private:
	glWindow* m_pWindowInstance = nullptr;
	std::unique_ptr<ScyllaContext> m_scyllaCtx = {};
	std::unique_ptr<IconList> m_processesIcons = {};

	Process m_currentProcess = {};
	ModuleInfo m_currentModule = {};
	std::uintptr_t m_uSelectedModuleImportBase = 0;
	std::uintptr_t m_uSelectedImportKey = 0;
	std::string m_strOEP = "";
	std::string m_strVA = "";
	std::string m_strSize = "";

	bool m_lockInterface = false;

	void getIatHexString( );

	void DisplayFilter( const std::string& filterTitle, std::string& outFilter, ImVec2 Size, bool bWithBeginChild );
	void DrawIconFontStatus( ImVec2 incPos, float size, int index );
	void ProcessesTab( );
	bool ModulesTab( );
	bool SwapIatFunctionShow( ImportThunk* importThunk );
	bool IatTab( );
	void ConfigTab( );

};