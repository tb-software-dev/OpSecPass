#include <iostream>
#include <cstring>
#include <sodium.h>
#include "MasterKey.h"
#include "AesGcm.h"
#include "SecureBuffer.h"
#include "PasswordManager.h"
#include "PasswordGenerator.h"

using namespace std;


int main()
{
	try
	{
		PasswordManager manager;
		string master = "Test";
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

    
    system("pause");
    return 0;
}