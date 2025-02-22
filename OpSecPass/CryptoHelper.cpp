#include "CryptoHelper.h"

using namespace std;

SecureString CryptoHelper::pbkdf2_derive_key(const SecureString& password,
											 const vector<uint8_t>& salt,
											 int iterations)
{
	// EVP_MAX_KEY_LENGTH gibt die maximale Schlüssellänge vor.
	vector<uint8_t> key(EVP_MAX_KEY_LENGTH);

    // Führe die Schlüsselableitung mit dem PBKDF2-Algorithmus durch.
    // - password.c_str(): Zeiger auf die Passwort-Zeichenkette.
    // - password.size(): Länge des Passworts.
    // - salt.data() und salt.size(): Zeiger und Länge des Salts.
    // - iterations: Anzahl der Iterationen, um Brute-Force-Angriffe zu erschweren.
    // - EVP_sha256(): Verwendet den SHA-256 Hash-Algorithmus.
    // - key.size() und key.data(): Länge und Speicherbereich des abgeleiteten Schlüssels.

    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt.data(),
        salt.size(), iterations, EVP_sha256(), key.size(), key.data()))
    {
        throw runtime_error("Key Derivation fehlgeschlagen");
    }

    return SecureString(reinterpret_cast<const char*>(key.data()), key.size());
}

// Implementierung der AES-Verschlüsselung in AES-256-CBC
vector<uint8_t> CryptoHelper::aes_encrypt(const SecureString& plaintext, const SecureString& key)
{
    // Erzeuge einen neuen Kontext für die Verschlüsselung
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
        throw runtime_error("Konnte EVP_CIPHER_CTX nicht erstellen");
    }

    // Bestimme die Länge des Initialisierungsvektors (IV) für AES-256-CBC
    int iv_length = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    vector<uint8_t> iv(iv_length);

    // Generiere einen kryptographischen zufälligen iv
    if (RAND_bytes(iv.data(), iv_length) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("IV-Generate Error");
    }

    // Initialisiere den Verschlüsselungskontext mit AES-256-CBC, dem Schlüssel und dem IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(key.c_str()), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Verschlüsselungsinitialisierung fehlgeschlagen");
    }

    // Ermittle die Blockgröße des Verschlüsselungsalgorithmus
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    // Berechne die maximale Länge des Ciphertexts (Klartextgröße + ein Block für Padding)
    int ciphertext_len = plaintext.size() + block_size;
    vector<uint8_t> ciphertext(ciphertext_len);

    int len;
    // Verschlüssle den Klartext in Blöcken
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
        reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Verschlüsselungsupdate fehlgeschlagen");
    }

    int total_len = len;

    // Finalisiere die Verschlüsselung, um das letzte Datenstück (inc. Padding zu verarbeiten
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Verschlüsselungs-finalisierung fehlgeschlagen");
    }

    total_len += len;

    // Passe die Größe des Ciphertext-Vektors an die tatsächliche Länge der verschlüsselten Daten an.
    ciphertext.resize(total_len);

    // Füge den IV am Anfang des Ciphertexts ein, damit er beim verschlüsseln verfügbar ist.
    ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());

    // Gib den Verschlüsselungskontext frei.
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Implementierung der AES - Entschlüsselung im Modus AES - 256 - CBC
SecureString CryptoHelper::aes_decrypt(const std::vector<uint8_t>&ciphertext,
    const SecureString & key) 
{
    // Erzeuge einen neuen Kontext für die Entschlüsselung.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("Konnte EVP_CIPHER_CTX nicht erstellen");

    // Bestimme die Länge des IVs.
    int iv_length = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    // Überprüfe, ob der Ciphertext lang genug ist, um einen IV zu enthalten.
    if (ciphertext.size() < static_cast<size_t>(iv_length))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ciphertext zu kurz");
    }

    // Extrahiere den IV aus dem Anfang des Ciphertexts.
    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + iv_length);
    // Der eigentliche verschlüsselte Text befindet sich nach dem IV.
    std::vector<uint8_t> actual_ciphertext(ciphertext.begin() + iv_length, ciphertext.end());

    // Initialisiere den Entschlüsselungskontext mit AES-256-CBC, dem Schlüssel und dem extrahierten IV.
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(key.c_str()), iv.data()) != 1) 
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Entschlüsselungsinitialisierung fehlgeschlagen");
    }

    // Bereite einen Puffer vor, um den entschlüsselten Klartext aufzunehmen.
    int plaintext_len = actual_ciphertext.size();
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    std::vector<uint8_t> plaintext(plaintext_len + block_size);

    int len;
    // Entschlüssele den Ciphertext in Blöcken.
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
        actual_ciphertext.data(), actual_ciphertext.size()) != 1) 
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Entschlüsselungsupdate fehlgeschlagen");
    }
    int total_len = len;

    // Finalisiere die Entschlüsselung, um das Padding zu verarbeiten.
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) 
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Entschlüsselungsfinalisierung fehlgeschlagen");
    }
    total_len += len;
    // Passe die Größe des Klartext-Puffers an die tatsächliche Länge der entschlüsselten Daten an.
    plaintext.resize(total_len);

    // Gib den Entschlüsselungskontext frei.
    EVP_CIPHER_CTX_free(ctx);

    // Gib den entschlüsselten Klartext als SecureString zurück.
    return SecureString(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
}
