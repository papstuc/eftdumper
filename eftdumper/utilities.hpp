#pragma once

#include <cstdint>

namespace utilities
{
	std::uint8_t* get_module(const char* module_name);
	std::uint8_t* pattern_scan(const char* module_name, const char* signature);
	std::uint8_t* pattern_scan(std::uint8_t* module, const char* signature);
	std::uint8_t* resolve_rip(std::uint8_t* address, std::uint32_t rva_offset, std::uint32_t rip_offset);
}
