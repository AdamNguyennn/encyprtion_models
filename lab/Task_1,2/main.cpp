#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include <cryptopp/files.h>
using CryptoPP::FileSource;

#include <iostream>
#include <fstream>
#include <streambuf>
#include "functions.h"
using namespace std;

int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;
    //Define the key and iv
    byte iv[AES::BLOCKSIZE];
    byte key[32], fkey[32];
    string plain;
    int type_encrption, type_input;

    // Switch case encryption
    cout << "Select type of input Secret Key and IV: " << endl;
    cout << "1. Input Secret Key and IV randomly: " << endl;
    cout << "2. Input Secret Key and IV from screen: " << endl;
    cout << "3. Input Secret Key and IV from file (using file name): " << endl;
    
    

    cout << "\nYour input: ";
    cin >> type_encrption;

    switch (type_encrption) {
        case 1:
            //  Key, IV randomly
            cout << "Case 1: Create Key, IV randomly" << endl;
            // Create random iv
            prng.GenerateBlock(iv, sizeof(iv));
            // Create random key
            prng.GenerateBlock(key, sizeof(key));
            break;
        case 2:
            // Input Key, IV
            //Define the key and iv
            cout << "Case 2: Insert Key, IV" << endl;
            cin >> iv;
            cin >> key;
            break;
        case 3:
            string key_file_name;
            cout << "Case 3: Get Key from file name" << endl;
            cout << "Insert your key file name: ";
            cin >> key_file_name;
            
            // convert string to char
            int n = key_file_name.length();
            char key_file[n + 1];
            strcpy(key_file, key_file_name.c_str());

            /* Reading key from file*/
            FileSource fs(key_file, false);
            /*Create space  for key*/ 
            CryptoPP::ArraySink copykey(key, sizeof(key));
            /*Copy data from AES_key.key  to  key */
            fs.Detach(new Redirector(copykey));
            // cout << infile <<endl;
            fs.Pump(sizeof(key));  // Pump first 32 bytes
            break;
    };

    // Switch case input
    cout << "\nSelect type of input ciphertext: " << endl;
    cout << "1. Input plain_text: " << endl;
    cout << "2. Input plain_text from file name: " << endl;
    

    cout << "\nYour input: ";
    cin >> type_input;

    switch (type_input) {
        case 1:
            cout << "Case 1: Input plain_text" << endl;
            cout << "Input plain text: ";
            cin >> plain;
            break;
        case 2:
            string file_name;
            cout << "Case 2: Input plain_text from file name" << endl;
            cout << "Input plain text: ";
            cin >> file_name;
            
            ifstream MyReadFile(file_name);
            // read one line only
            getline (MyReadFile, plain);

            cout << plain << endl;
            break;
    };
    


    
    string sha1_digest_result, cipher, encoded, recovered;

    //Print Data
    cout << "Plain text: " << plain << endl;
    cout << "Key: " << PrettyPrint(key, AES::DEFAULT_KEYLENGTH) << endl;
	cout << "iv: " << PrettyPrint(iv, AES::BLOCKSIZE) << endl;
 
    //Encrypt
    cipher = CBCMode_Encrypt(plain, key, sizeof(key), iv);
    cout << "Cipher Text: " << PrettyPrint(cipher) << endl;
    
    //Decrypt
    recovered = CBCMode_Decrypt(cipher, key, sizeof(key), iv);
    cout << "Recovered text: " << recovered << endl;
    
    //Write to file
    
    ofstream myfile;
    myfile.open ("result.txt");
    myfile << buffer;
    myfile.close();
    return 0;
}



