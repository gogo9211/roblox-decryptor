#pragma once

#include <cstdint>
#include <utility>
#include <functional>

namespace decryptor::utils
{
	class pe
	{
	public:
		struct range_t
		{
			std::uintptr_t base;
			std::uint32_t size;
		};

		struct section_t
		{
			range_t virtual_range;
			range_t raw_range;
		};

	public:
		pe(const char* mod);
		pe(std::uintptr_t mod);

		section_t get_section(const char* section) const;

		std::uintptr_t get_image_base() const;
		std::uint32_t get_image_size() const;

	private:
		void parse_headers();

	private:
		std::uintptr_t base;

		void* nt_headers;
	};
}