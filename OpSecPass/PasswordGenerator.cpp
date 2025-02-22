#include "PasswordGenerator.h"

using namespace std;

SecureString PasswordGenerator::generate(size_t length, bool use_symbols)
{
	const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	const string symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

	string valid_chars = chars;

	if (use_symbols)
	{
		valid_chars += symbols;
	}

	SecureString password;

	for (size_t i = 0; i < length; i++)
	{
		password += valid_chars[secure_rand(valid_chars.size())];
	}

	return password;
}

size_t PasswordGenerator::secure_rand(size_t max)
{
	unsigned int result;

	if (RAND_bytes(reinterpret_cast<unsigned char*>(&result), sizeof(result)) != 1)
	{
		throw runtime_error("Generate Error");
	}

	return result % max;
}