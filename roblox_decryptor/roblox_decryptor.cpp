#include <iostream>

#include "decryptor/decryptor.hpp"

using namespace decryptor;

int main()
{
	std::printf("Starting decryptor\n");

	code_decryptor static_decryptor{ "RobloxPlayerBeta.dll", "RobloxPlayerBeta.exe", "decrypted.bin" };

	if (!static_decryptor.is_initialized())
	{
		std::printf("Decryptor failed to initialize\n");

		std::cin.get();

		return 1;
	}

	static_decryptor.decrypt();

	std::printf("Decryptor successfully finished\n");

	std::cin.get();
}