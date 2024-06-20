#pragma once
#ifdef _WIN32 
#include <Windows.h>
#endif
#include "Thirdparty/GLFW/glfw3.h"
#include "Thirdparty/ImGui/imgui.h"
#include <vector>
#include <functional>
#include <thread>

class gl_window;

using t_frame =  std::function<void( gl_window* )>;

class gl_window
{
private:

	std::thread me_thread {};

	bool b_goodbye = false;

	const char* caption = nullptr;

	int status = 0;

	GLFWwindow* window = nullptr;

	t_frame  frame_controls = {};

	bool me_close = false;

	static void run_thead( gl_window* inst );

	std::vector<ImFont*> fonts {};

public:

	static gl_window* i( );


	float f_top = 0;

	float f_left = 0;

	int width = 0;

	int height;

	void create( );

	bool show_window = true;

	void routine( );

	gl_window( const char* w_caption, int w_width, int w_height );

	void set_frame_controls( t_frame f_controls );

	void set_size( int w_width, int w_height );

	ImVec2 get_size( ) const;

	void set_frame_pos( float w_left, float w_top );

	ImVec2 get_frame_pos( ) const;

	void center( ) const;

	void close( ) const;

	void goodbye( );

	std::vector<ImFont*> get_fonts( ) const;
};
