#pragma once

#include "SecureString.h"
#include <string>
#include <stdexcept>
#include <openssl/rand.h>



class PasswordGenerator
{
public:

	static SecureString generate(size_t length, bool use_symbols = true);

private:

	static size_t secure_rand(size_t max);
};
