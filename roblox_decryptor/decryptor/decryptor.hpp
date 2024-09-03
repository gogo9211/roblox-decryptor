#pragma once

#include <cstdint>
#include <string>
#include <filesystem>
#include <fstream>
#include <array>

namespace decryptor
{
	class code_decryptor
	{
	public:
		code_decryptor(const std::filesystem::path& hyperion, const std::filesystem::path& roblox, const std::string& out_filename);
		~code_decryptor();

		void decrypt();

		bool is_initialized() const;

	private:
		std::uintptr_t get_base_from_handle(void* handle) const;
		
	private:
		void* hyperion_handle;
		void* roblox_handle;

		std::uintptr_t page_info_base;

		std::ofstream out_file;
	};
}