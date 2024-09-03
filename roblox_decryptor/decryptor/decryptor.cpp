#include "decryptor.hpp"

#include "utils/memory.hpp"
#include "utils/pe.hpp"

#include <Windows.h>

#include <vendor/chacha20/chacha20.hpp>

namespace decryptor
{
	code_decryptor::code_decryptor(const std::filesystem::path& hyperion, const std::filesystem::path& roblox, const std::string& out_filename) : page_info_base{ 0 }
	{
		// Loading the module directly so we can work with memory mapped offsets
		hyperion_handle = LoadLibraryExA(hyperion.string().c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
		roblox_handle = LoadLibraryExA(roblox.string().c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);

		if (!roblox_handle || !hyperion_handle)
			return;

		utils::pe roblox_image{ get_base_from_handle(roblox_handle) };
		utils::pe hyperion_image{ get_base_from_handle(hyperion_handle) };

		const auto roblox_code = roblox_image.get_section(".text");
		const auto hyperion_code = hyperion_image.get_section(".byfron");

		DWORD old;
		VirtualProtect(reinterpret_cast<LPVOID>(roblox_code.base), roblox_code.size, PAGE_READWRITE, &old);

		// Attempt to automatically locate the page info array
		constexpr std::array<std::uint8_t, 6> constant_sig = { 0x10, 0x27, 0x00, 0x00, 0xCC, 0x29 };
		constexpr std::array<std::uint8_t, 3> lea_sig = { 0x04, 0xCC, 0x8D };

		const auto constant_mov = utils::signature_scan(hyperion_code.base, hyperion_code.size, constant_sig);

		if (!constant_mov)
			return;

		auto page_info_lea = utils::signature_scan(constant_mov, 0x100, lea_sig);

		if (!page_info_lea)
			return;

		// Plus one because we include the end of the shl reg, 4 instruction
		page_info_lea += 1;
			
		const auto dest = page_info_lea + *reinterpret_cast<std::int32_t*>(page_info_lea + 3) + 7;

		page_info_base = dest;

		std::ifstream src{ roblox, std::ios::binary };

		out_file = std::ofstream{ out_filename, std::ios::binary };
		out_file << src.rdbuf();

		src.close();
	}

	code_decryptor::~code_decryptor()
	{
		if (hyperion_handle)
			FreeLibrary(static_cast<HMODULE>(hyperion_handle));

		if (roblox_handle)
			FreeLibrary(static_cast<HMODULE>(roblox_handle));
	}

	bool code_decryptor::is_initialized() const
	{
		return page_info_base != 0;
	}

	void code_decryptor::decrypt()
	{
		utils::pe roblox_image{ get_base_from_handle(roblox_handle) };
		utils::pe hyperion_image{ get_base_from_handle(hyperion_handle) };

		const auto roblox_code = roblox_image.get_section(".text");
		const auto hyperion_code = hyperion_image.get_section(".byfron");

		for (auto target_page = roblox_code.base; target_page < roblox_code.base + roblox_code.size; target_page += 0x1000)
		{
			const auto target_page_number = (target_page - roblox_image.get_image_base()) / 0x1000;
			const auto target_page_info_base = page_info_base + (target_page_number % 10000) * 0x10;

			const auto page_info = *reinterpret_cast<std::uintptr_t*>(target_page_info_base);
			const auto page_size = *reinterpret_cast<std::uint32_t*>(target_page_info_base + 0x8);

			std::array<std::uint8_t, 32> key{};
			std::memcpy(key.data(), reinterpret_cast<void*>(page_info), page_size);

			chacha20_context ctx;
			chacha20_init_context(&ctx, key.data(), 0);
			chacha20_xor(&ctx, reinterpret_cast<uint8_t*>(target_page), 0x1000);
		}

		// Seek to the first section after the PE headers, assuming it should be code
		out_file.seekp(0x600);
		out_file.write(reinterpret_cast<char*>(roblox_code.base), roblox_code.size);
		out_file.flush();
	}

	std::uintptr_t code_decryptor::get_base_from_handle(void* handle) const
	{
		return reinterpret_cast<std::uintptr_t>(handle);
	}
}