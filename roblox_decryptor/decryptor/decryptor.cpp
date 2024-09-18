#include "decryptor.hpp"

#include "utils/memory.hpp"
#include "utils/pe.hpp"

#include <Windows.h>
#include <intrin.h>

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

		constexpr std::array<std::uint8_t, 16> short_sig = { 0xBA, 0xCC, 0xCC, 0xCC, 0xCC, 0x45, 0xCC, 0xCC, 0x48, 0x8D, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xEB };
		constexpr std::array<std::uint8_t, 17> long_sig = { 0x41, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x45, 0xCC, 0xCC, 0x48, 0x8D, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xEB };

		auto int3_info = utils::signature_scan(hyperion_code.base, hyperion_code.size, long_sig);
		is_long_info = true;

		if (!int3_info) {
			int3_info = utils::signature_scan(hyperion_code.base, hyperion_code.size, short_sig);
			if (!int3_info) {
				std::printf("Failed to locate INT3 info!\n");
				return;
			}

			is_long_info = false;
		}

		int3_info_base = int3_info;

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

		decrypt_int3(); // Begin decrypting INT3 after the code.

		// Seek to the first section after the PE headers, assuming it should be code
		out_file.seekp(0x600);
		out_file.write(reinterpret_cast<char*>(roblox_code.base), roblox_code.size);
		out_file.flush();
	}

	void code_decryptor::decrypt_int3()
	{
		std::uintptr_t roblox_base = get_base_from_handle(roblox_handle);
		std::uintptr_t hyperion_base = get_base_from_handle(hyperion_handle);

		// Sorry for naming convention, it's just my style.
		std::uint32_t arraySize = *(std::uint32_t*)(int3_info_base + 1 + is_long_info);
		std::uintptr_t int3_lea = (int3_info_base + 8 + is_long_info);
		std::uintptr_t decryptionTable = int3_lea + *(std::int32_t*)(int3_lea + 3) + 7;

		for (std::uint32_t i = 0; i < arraySize; i++) {
			std::uintptr_t baseValue = decryptionTable + ((std::uintptr_t)i * 0x18);
			std::uintptr_t address = roblox_base + *(uint32_t*)(baseValue + 0xA);
			std::uint16_t instrLength = (*(std::uint16_t*)(baseValue) >> 11) & 7; 

			std::uint8_t decrypted[8]{ 0 };
			std::uint32_t master_fish = *(std::uint8_t*)(baseValue + 2);
			__m128i xor_fish = _mm_xor_si128(
				_mm_insert_epi16(
					_mm_cvtsi32_si128(master_fish | ((std::uint8_t)_rotr8(master_fish, 1) << 8)),
					(std::uint8_t)_rotl8(master_fish, 6) | ((std::uint8_t)_rotl8(master_fish, 5) << 8),
					1),
				_mm_cvtsi32_si128(*(std::uint32_t*)(baseValue + 3))
			);

			*(std::uint32_t*)(decrypted) = _mm_cvtsi128_si32(xor_fish);
			decrypted[4] = *(std::uint8_t*)(baseValue + 7) ^ _rotl8(master_fish, 4);
			decrypted[5] = *(std::uint8_t*)(baseValue + 8) ^ _rotl8(master_fish, 3);
			decrypted[6] = *(std::uint8_t*)(baseValue + 9) ^ _rotl8(master_fish, 2);

			std::memcpy((void*)address, decrypted, instrLength);
		}
	}

	std::uintptr_t code_decryptor::get_base_from_handle(void* handle) const
	{
		return reinterpret_cast<std::uintptr_t>(handle);
	}
}