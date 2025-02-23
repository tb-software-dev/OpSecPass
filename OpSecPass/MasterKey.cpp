#include "MasterKey.h"
#include "KeyDerivation.h"
#include "Security.h"
#include <stdexcept>

using namespace std;

void MasterKey::initialize(const SecureBuffer& password)
{
	SecureBuffer salt(32);
	Security::secure_random(salt.data(), salt.size());

	KeyDerivation kd;
	key_ = kd.derive_key(password, salt);

	if (sodium_mlock(key_.data(), key_.size()) != 0)
	{
		throw runtime_error("Memory locking for master key failed");
	}
}

const SecureBuffer& MasterKey::get_key() const
{
	if (key_.size() == 0)
	{
		throw runtime_error("Key not initialized");
	}

	return key_;
}