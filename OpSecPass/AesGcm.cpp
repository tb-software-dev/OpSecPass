#include "AesGcm.h"
#include <stdexcept>
#include <openssl/evp.h>
#include <sodium.h>

using namespace std;

// Konstruktur um die Ergebnisse der Vershlüsselung zu speichern (IV)
AesGcm::EncryptedData::EncryptedData(size_t plaintext_size)
	: iv(IV_LENGTH),	// Initialisiert den IV-Vektor mit einer festen Länge
	ciphertext(plaintext_size),		// Reserviert Speicher für den Ciphertext, basierend auf der Größe von plaintext
	tag(TAG_LENGTH)				// Intialisiert den TAG vector mit einer festen Länge
{

}


AesGcm::EncryptedData AesGcm::encrypt(const SecureBuffer& plaintext, const SecureBuffer& key)
{
	// Überprüft ob der Key tatsächlich 32 Bytes(256 Bit) lang ist
	if (key.size() != 32)
	{
		throw runtime_error("Invalid key size");
	}

	EncryptedData result(plaintext.size());

	// Generiert ein zufälligen IV mit der angegebenen Länge
	randombytes_buf(result.iv.data(), IV_LENGTH);

	// Erzeugt einen neuen Verschlüsselungs Kontext mit Openssl
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
	{
		throw runtime_error("cipher Context Create ERROR!!!");
	}

	// Anwenden der AES-256-GCM Verschlüsselung
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), result.iv.data()) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		throw runtime_error("Encryption Init failed");
	}

	int out_len = 0;
	// Finalisiert die Verschlüsselung , sodass eventuell verbliebene Daten verarbeitet werden
	if(EVP_DecryptFinal_ex)




}