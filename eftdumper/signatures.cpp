#include <fstream>
#include <filesystem>

#include "signatures.hpp"
#include "utilities.hpp"
#include "json.hpp"

bool signatures::parse_json(const wchar_t* file_path, std::vector<signatures::signature_t>& sigs)
{
	if (!std::filesystem::exists(std::filesystem::path(file_path)))
	{
		return false;
	}

	std::ifstream stream(file_path);
	nlohmann::json json;

	try
	{
		json = nlohmann::json::parse(stream);
	}
	catch (nlohmann::json::exception&)
	{
		return false;
	}

	for (nlohmann::json& item : json)
	{
		signatures::signature_t sig = { };

		item["name"].get_to(sig.name);
		item["module"].get_to(sig.module);
		item["signature"].get_to(sig.signature);
		item["rva_offset"].get_to(sig.rva_offset);
		item["rip_offset"].get_to(sig.rip_offset);

		sigs.push_back(sig);
	}

	return true;
}

bool signatures::dump_offsets(std::vector<signatures::signature_t>& sigs)
{
	if (sigs.size() <= 0)
	{
		return false;
	}

	for (signatures::signature_t& item : sigs)
	{
		std::uint8_t* module_handle = utilities::get_module(item.module.c_str());

		if (!module_handle)
		{
			return false;
		}

		std::uint8_t* result = utilities::pattern_scan(module_handle, item.signature.c_str());

		if (!result)
		{
			return false;
		}

		std::uint8_t* offset = reinterpret_cast<std::uint8_t*>(utilities::resolve_rip(result, item.rva_offset, item.rip_offset) - module_handle);

		if (!offset)
		{
			return false;
		}

		printf("[%s] -> %s: 0x%p\n", item.module.c_str(), item.name.c_str(), offset);
	}

	return true;
}