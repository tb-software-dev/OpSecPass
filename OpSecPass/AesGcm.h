#pragma once

#include "SecureBuffer.h"

using namespace std;

class AesGcm
{
public:

	struct EncryptedData
	{
		SecureBuffer iv;
		SecureBuffer ciphertext;
		SecureBuffer tag;

        // Konstruktor: Initialisiere Member mit korrekter Größe
        EncryptedData(size_t plaintext_size)
            : iv(IV_LENGTH),
            ciphertext(plaintext_size),
            tag(TAG_LENGTH)
        {
        }

        // Move-Konstruktor (manuell implementiert)
        EncryptedData(EncryptedData&& other) noexcept
            : iv(std::move(other.iv)),
            ciphertext(std::move(other.ciphertext)),
            tag(std::move(other.tag))
        {
        }

        // Move-Zuweisung (manuell implementiert)
        EncryptedData& operator=(EncryptedData&& other) noexcept
        {
            iv = std::move(other.iv);
            ciphertext = std::move(other.ciphertext);
            tag = std::move(other.tag);
            return *this;
        }

	};

	static EncryptedData encrypt(const SecureBuffer& plaintext, const SecureBuffer& key);
	static SecureBuffer decrypt(const EncryptedData& data, const SecureBuffer& key);

private:
	static constexpr size_t IV_LENGTH = 12;
	static constexpr size_t TAG_LENGTH = 16;
};
