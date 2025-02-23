#include "KeyDerivation.h"
#include <stdexcept>
#include <sodium.h>

using namespace std;

// Ableiten eines Keys aus dem Passwort und Salt mit Argon2
SecureBuffer KeyDerivation::derive_key(const SecureBuffer& password,
									   const SecureBuffer& salt,
									   uint32_t iterations,
									   uint32_t memory,
									   uint32_t parallelism)
{
	// Generierung eines SecureBuffers für den Key mit einer festen Größe von 32 Bytes(256 Bit)
	SecureBuffer key(32);

	// key.data, key.size : Speicherbereich und Länge die in den key geschrieben werden
	if (crypto_pwhash(key.data(), key.size(),
		reinterpret_cast<const char*>(password.data()),
		password.size(), salt.data(),
		iterations, memory,
		crypto_pwhash_ALG_ARGON2ID13) != 0)
	{
		throw runtime_error("Key derivation failed");
	}
	return key;
}