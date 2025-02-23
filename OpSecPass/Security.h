#pragma once

#include "SecureBuffer.h"
#include <cstddef>

namespace Security
{
	void secure_random(void* buf, size_t length);
	bool const_time_compare(const SecureBuffer& a, const SecureBuffer& b);
}
