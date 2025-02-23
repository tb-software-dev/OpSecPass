#pragma once

#include "SecureBuffer.h"

class MasterKey
{
public:
	void initialize(const SecureBuffer& password);
	const SecureBuffer& get_key() const;

private:
	SecureBuffer key_{ 0 };
};
