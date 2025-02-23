#pragma once

#include "SecureBuffer.h"
#include <cstdint>

class KeyDerivation
{
public:
	SecureBuffer derive_key(const SecureBuffer& password, const SecureBuffer& salt,
							uint32_t iterations = 3,
							uint32_t memory = 1 << 17,// 128 MB
							uint32_t parallelism = 4);
};
