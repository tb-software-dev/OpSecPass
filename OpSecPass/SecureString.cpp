#include "SecureString.h"

using namespace std;

SecureString::~SecureString()
{
	secure_erase();
}

void SecureString::secure_erase()
{
	fill(begin(), end(), 0);
}