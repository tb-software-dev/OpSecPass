#pragma once

#include <vector>
#include <memory>
#include <stdexcept>
#include <sodium.h>

using namespace std;

class SecureBuffer
{
public:
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();

    // Move-Semantik explizit erlauben
    SecureBuffer(SecureBuffer&&) = default;
    SecureBuffer& operator=(SecureBuffer&&) = default;

    // Kopieren verbieten
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    uint8_t* data();
    const uint8_t* data() const;
    size_t size() const;

private:
    unique_ptr<vector<uint8_t>> data_;
};