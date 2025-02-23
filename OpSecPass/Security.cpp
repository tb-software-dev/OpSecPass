#include "Security.h"
#include <sodium.h>
#include <stdexcept>

namespace Security 
{

    void secure_random(void* buf, size_t length)
    {
        randombytes_buf(buf, length);
    }

    bool constant_time_compare(const SecureBuffer& a, const SecureBuffer& b) 
    {
        if (a.size() != 32 || b.size() != 32)
        {
            throw std::runtime_error("Buffers must be 32 bytes for constant time comparison");
        }
        return crypto_verify_32(a.data(), b.data()) == 0;
    }

} // namespace Security
