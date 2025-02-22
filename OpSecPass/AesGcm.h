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

		// Konstruktor: plaintext_size wird benötigt, um den Ciphertext-Puffer anzulegen
		EncryptedData(size_t plaintext_size);
	};

	static EncryptedData encrypt(const SecureBuffer& plaintext, const SecureBuffer& key);
	static SecureBuffer decrypt(const EncryptedData& data, const SecureBuffer& key);

private:
	static constexpr size_t IV_LENGTH = 12;
	static constexpr size_t TAG_LENGTH = 16;
};
