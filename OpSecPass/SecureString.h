#pragma once

#include <string>
#include <algorithm>

using namespace std;

// Sichere Speicherung sensibler Daten
class SecureString : public string
{
public:

	SecureString() : std::string() {}

	// Konstruktoren explizit definieren
	SecureString(const std::string& s) : std::string(s) {}
	SecureString(const char* s) : std::string(s) {}

	// Neuer Konstruktor: Erlaubt die Initialisierung mit (const char*, size_t)
	SecureString(const char* s, size_t count) : std::string(s, count) {}



	~SecureString();
	void secure_erase();
};