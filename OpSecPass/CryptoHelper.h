#pragma once

#include "SecureString.h"
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

class CryptoHelper
{
public:
	//=========================================================================//
	//Leitet mit PBKDF2 einen Schlüssel aus einen Passwort und einen Salt ab   //
	// - password: Dass Passwort als SecureString.							   //
	// - salt: Ein Zufallswert, der als vector von Bytes übergeben wird		   //
	// - iterations: Anzahl der Iteration (Schutzmaßnahme gegen Brute-Force)   //
	//=========================================================================//
	static SecureString pbkdf2_derive_key(const SecureString& password,
										const vector<uint8_t>& salt,
										int iterations = 10000);

	//==========================================================================//
	// Verschlüsselt einen Klartext mittels AES									//
	//  -plaintext: Der zu verschlüsselnde Text als SecureString				//
	//  -key: Der Schlüssel als SecureString									//
	// Gibt den Verschlüsselten Text (Ciphertext) als vector zurück				//
	//==========================================================================//
	static vector<uint8_t> aes_encrypt(const SecureString& plaintext,
										const SecureString& key);


	//===========================================================================//
	// Entschlüsselt einen Ciphertext und liefert den ursprünglichen Klartext	 //
	//  -ciphertext: Der verschlüsselte Text als vector							 //
	//  -key: Der Schlüssel als SecureString									 //
	//===========================================================================//
	static SecureString aes_decrypt(const vector<uint8_t>& ciphertext,
									const SecureString& key);

};
