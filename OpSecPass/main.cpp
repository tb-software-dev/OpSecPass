#include <iostream>
#include "PasswordManager.h"
#include "PasswordGenerator.h"
#include "SecureString.h"
#include <sodium.h>

using namespace std;


int main()
{
	try
	{
		PasswordManager manager;
		string master = "80838083";
		cout << "Gib dein Master-Passwort ein: ";
		cin >> master;
		SecureString master_password(master);
		manager.initialize(master_password);

		manager.add_entry("example.com", "user@example.com", PasswordGenerator::generate(16));

		manager.save_vault("vault.dat");
		cout << "Vault gespeichert" << endl;

	}
	catch (const exception& ex)
	{
		cerr << "Fehler: " << ex.what() << endl;
		return 1;
	}




	return 0;
}