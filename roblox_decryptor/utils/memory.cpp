#include "memory.hpp"

constexpr auto page_size = 0x1000;

namespace decryptor::utils
{
	std::uintptr_t page_align(std::uintptr_t addr)
	{
		return (addr + page_size) & ~(page_size - 1);
	}
}