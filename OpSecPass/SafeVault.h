#pragma once

#include <vector>
#include <array>
#include <openssl/evp.h>
#include <oqs/oqs.h>
#include <sodium.h>

using namespace std;

using namespace std;

// Safevault implementiert  (AES-256-GCM + Kyber-1024)

class SafeVault
{
public:

	struct HybridCiphertext
	{
		vector<uint8_t> classic_ciphertext;
		vector<uint8_t> kyber_ciphertext;
		array<uint8_t, 24> nonce;

	};

	HybridCiphertext hybrid_encrypt(const vector<uint8_t>& plaintext);

private:
	array<uint8_t, 24> generate_nonce();

	void aes_encrypt(const vector<uint8_t>& plaintext, const array<uint8_t, 24>& nonce, vector<uint8_t>& ciphertext);

	vector<uint8_t> hkdf_derive(const vector<uint8_t>& shared_secret, const vector<uint8_t>& secret_key);
	

};
