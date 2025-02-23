#include "AesGcm.h"
#include <stdexcept>
#include <openssl/evp.h>
#include <sodium.h>
#include "SecureBuffer.h"

using namespace std;




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
	if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &out_len, plaintext.data(), plaintext.size()) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		throw runtime_error("Encryption update failed");
	}

	int final_out_len = 0;
	// Finalisiert die Verschlüsselung
	if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + out_len, &final_out_len) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		throw runtime_error("Encryption finalization failed");
	}

    // Extrahiert den Authentifizierungstag (Tag) aus dem Verschlüsselungskontext.
    // Dieser Tag wird für die Integritätsprüfung beim Entschlüsseln benötigt.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, result.tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to get GCM tag");
    }

    // Gibt den Verschlüsselungskontext frei.
    EVP_CIPHER_CTX_free(ctx);
    // Gibt das Ergebnis zurück, das den IV, den verschlüsselten Text und den Authentifizierungstag enthält.
    return result;
}

// Entschlüsselungsmethode: Nimmt ein EncryptedData-Objekt und den Schlüssel als SecureBuffer entgegen
// und gibt den entschlüsselten Klartext als SecureBuffer zurück.
SecureBuffer AesGcm::decrypt(const EncryptedData& data,
    const SecureBuffer& key)
{
    // Überprüft, ob der Schlüssel exakt 32 Byte (256 Bit) lang ist.
    if (key.size() != 32)
        throw runtime_error("Invalid key size");

    // Erstellt einen SecureBuffer für den Klartext, der dieselbe Größe wie der Ciphertext hat.
    SecureBuffer plaintext(data.ciphertext.size());

    // Erzeugt einen neuen Entschlüsselungskontext.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw runtime_error("Failed to create cipher context");

    // Initialisiert den Kontext für AES-256-GCM-Entschlüsselung mit dem Schlüssel und IV.
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), data.iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption initialization failed");
    }

    int out_len = 0;
    // Entschlüsselt den Ciphertext und speichert den Klartext im plaintext-Puffer.
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
        data.ciphertext.data(), data.ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption update failed");
    }

    // Setzt den erwarteten Authentifizierungstag im Kontext.
    // Dies ermöglicht OpenSSL, die Integrität der Daten beim Finalisieren zu überprüfen.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH,
        const_cast<uint8_t*>(data.tag.data())) != 1) 
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set GCM tag");
    }

    // Finalisiert die Entschlüsselung.
    // Wenn die Authentifizierung fehlschlägt (z. B. durch einen falschen Tag), schlägt die Funktion fehl.
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) 
    {
        throw runtime_error("Decryption failed: Tag mismatch or data corrupted");
    }

    // Gibt den entschlüsselten Klartext zurück.
    return plaintext;
}





