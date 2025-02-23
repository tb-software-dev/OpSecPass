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
	
		PasswordManager manager;
		PasswordGenerator generator;
		string master = "PLACEHOLDER";
		cout << "Gib dein Master-Passwort ein: ";
		cin >> master;
		SecureString master_password(master);
		manager.initialize(master_password);
		cout << generator.generate(30) << endl;

		

	
	

    
    system("pause");
    return 0;
}