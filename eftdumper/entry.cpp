#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#include "utilities.hpp"
#include "signatures.hpp"
#include "console.hpp"

DWORD WINAPI start_dumping(void* instance)
{
	if (!console::is_allocated())
	{
		console::allocate();
	}

	std::cout << "File path: ";
	std::wstring file_path;

	std::wcin >> file_path;

	std::vector<signatures::signature_t> sigs = { };
	if (!signatures::parse_json(file_path.c_str(), sigs))
	{
		std::cout << "failed to parse json!" << std::endl;
		return FALSE;
	}

	if (!signatures::dump_offsets(sigs))
	{
		std::cout << "failed to dump offsets!" << std::endl;
		return FALSE;
	}

	std::this_thread::sleep_for(std::chrono::seconds(10));

	console::free();
	FreeLibraryAndExitThread(static_cast<HMODULE>(instance), 0);

	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, std::uint32_t call_reason, void* reserved)
{
	switch (call_reason)
	{
		case DLL_PROCESS_ATTACH:
			if (HANDLE handle = CreateThread(nullptr, 0, start_dumping, instance, 0, nullptr))
			{
				CloseHandle(handle);
			}
			break;

		case DLL_THREAD_ATTACH:
			break;

		case DLL_THREAD_DETACH:
			break;

		case DLL_PROCESS_DETACH:
			break;

		default:
			break;
	}

	return TRUE;
}