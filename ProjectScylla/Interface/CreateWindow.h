#pragma once
#ifdef _WIN32 
#include <Windows.h>
#endif
#include "Thirdparty/GLFW/glfw3.h"
#include "Thirdparty/ImGui/imgui.h"
#include <vector>
#include <functional>
#include <thread>

class glWindow;

using tFrame =  std::function<void( glWindow* )>;

class glWindow
{
private:

	std::thread m_thread {};

	bool m_bGoodbye = false;

	const char* m_pCaption = nullptr;

	int m_nStatus = 0;

	GLFWwindow* m_pWindow = nullptr;

	tFrame  m_CallbackFrameControls = {};

	bool m_bMeClose = false;

	static void runThread( glWindow* inst );

	std::vector<ImFont*> m_vFonts {};

public:

	static glWindow* i( );

	float m_fTop = 0;

	float m_fLeft = 0;

	int m_nWidth = 0;

	int m_nHeight;

	void create( );

	bool m_bShowWindow = true;

	void routine( );

	glWindow( const char* pCaption, int nWidth, int nHeight );

	void setFrameControls( tFrame funcControls );

	void setSize( int nWidth, int nHeight );

	ImVec2 getSize( ) const;

	void setFramePos( float fLeft, float fTop );

	ImVec2 getFramePos( ) const;

	void center( ) const;

	void close( ) const;

	void goodbye( );

	ImFont* getFont( int index ) const;
};
