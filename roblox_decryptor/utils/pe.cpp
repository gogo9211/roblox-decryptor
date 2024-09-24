#include "pe.hpp"

#include <Windows.h>
#include <cstring>

namespace decryptor::utils
{
	pe::pe(const char* mod)
	{
		base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(mod));

		parse_headers();
	}

	pe::pe(std::uintptr_t mod)
	{
		base = mod;

		parse_headers();
	}

	pe::section_t pe::get_section(const char* section) const
	{
		const auto nt_header = static_cast<IMAGE_NT_HEADERS*>(nt_headers);

		const auto section_headers = IMAGE_FIRST_SECTION(nt_header);

		for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
		{
			if (std::strcmp(reinterpret_cast<const char*>(section_headers[i].Name), section) == 0)
			{
				std::uintptr_t section_base = base + section_headers[i].VirtualAddress;
				std::uint32_t section_size = section_headers[i].Misc.VirtualSize;

				return { { section_base, section_size }, { section_headers[i].PointerToRawData, section_headers[i].SizeOfRawData } };
			}
		}

		return { 0, 0, 0, 0 };
	}

	std::uintptr_t pe::get_image_base() const
	{
		return base;
	}

	std::uint32_t pe::get_image_size() const
	{
		return static_cast<IMAGE_NT_HEADERS*>(nt_headers)->OptionalHeader.SizeOfImage;
	}

	void pe::parse_headers()
	{
		nt_headers = reinterpret_cast<void*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
	}
}