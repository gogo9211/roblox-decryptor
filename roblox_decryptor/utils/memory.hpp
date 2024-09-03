#pragma once

#include <cstdint>
#include <array>

namespace decryptor::utils
{
	template<std::size_t N>
	std::uintptr_t signature_scan(std::uintptr_t address, std::uint32_t size, const std::array<std::uint8_t, N>& pattern)
	{
		const auto data = reinterpret_cast<const std::uint8_t*>(address);

		for (auto i = 0; i <= size - N; ++i)
		{
			auto match = true;

			for (auto j = 0; j < N; ++j)
			{
				if (pattern[j] != 0xCC && data[i + j] != pattern[j])
				{
					match = false;

					break;
				}
			}

			if (match)
			{
				return address + i;
			}
		}

		return 0;
	}

	std::uintptr_t page_align(std::uintptr_t addr);
}