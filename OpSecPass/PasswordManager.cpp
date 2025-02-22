#include "PasswordManager.h"
#include "CryptoHelper.h"
#include <fstream>
#include <stdexcept>
#include <openssl/rand.h>

using namespace std;

void PasswordManager::initialize(const SecureString& master_password)
{
	// Generiere ein Salt
	salt_.resize(16);

	if (RAND_bytes(salt_.data(), salt_.size()) != 1)
	{
		throw runtime_error("Salt-Generierung fehlgeschlagen");
	}

	// Leitet den Schlüssel ab 
	derived_key_ = CryptoHelper::pbkdf2_derive_key(master_password, salt_);
}

void PasswordManager::add_entry(const string& service, const string& username,
	const SecureString& password)
{
	entries_.emplace_back(service, username, password);
}

void PasswordManager::save_vault(const string& filename)
{
	// Serialisiere die Einträge
	string serialized;

	for (const auto& entry : entries_)
	{
		const string& service = get<0>(entry);
		const string& username = get<1>(entry);
		const SecureString& password = get<2>(entry);
		serialized += service + "|" + username + "|" + password + "\n";
	}

	SecureString serialized_secure(serialized);

	// Verschlüssle die Serialisierten Daten
	vector<uint8_t> ciphertext = CryptoHelper::aes_encrypt(serialized_secure, derived_key_);

	ofstream out(filename, ios::binary);
	if (!out)
	{
		throw runtime_error("Datei konnte zum schreiben nicht geöffnet werden");
	}

	// Schreibe zuerst das Salt und dann den verschlüsselten Vault (der den IV enthält)
	out.write(reinterpret_cast<const char*>(salt_.data()), salt_.size());
	out.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
	out.close();
}