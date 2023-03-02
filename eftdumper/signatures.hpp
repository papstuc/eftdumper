#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace signatures
{
	typedef struct _signature_t
	{
		std::string name;
		std::string module;
		std::string signature;
		std::uint32_t rva_offset;
		std::uint32_t rip_offset;
	} signature_t;

	bool parse_json(const wchar_t* file_path, std::vector<signatures::signature_t>& sigs);
	bool dump_offsets(std::vector<signatures::signature_t>& sigs);
}