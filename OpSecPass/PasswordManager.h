#pragma once

#include "SecureString.h"
#include <vector>
#include <tuple>
#include <string>
#include <cstdint>

using namespace std;

class PasswordManager
{
public:
	void initialize(const SecureString& master_password);
	void add_entry(const string& service, const string& username, const SecureString& password);
	void save_vault(const string& filename);


private:

	vector<uint8_t> salt_;
	vector<tuple<string, string, SecureString>> entries_;
	SecureString derived_key_;
};