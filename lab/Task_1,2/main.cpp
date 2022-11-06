#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include "functions.h"

using namespace std;

int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;
    //Define the key and iv
    byte iv[AES::BLOCKSIZE];
    byte key[32], fkey[32];
    int type_encrption;

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
            cout << "Case 3: Get Key from file name" << endl;
            /* Reading key from file*/
            // FileSource fs("AES_key.key", false);
            /*Create space  for key*/ 
            // CryptoPP::ArraySink copykey(key, sizeof(key));
            /*Copy data from AES_key.key  to  key */ 
            // fs.Detach(new Redirector(copykey));
            // fs.Pump(sizeof(key));  // Pump first 32 bytes
            break;
        default:
            cout << "Nothing" << endl;
            break;
            // Go to CBC
    };

    
    // string plain;
    // cout << "Insert plain text: ";
    // // cin >> plain;
    // getline(cin, plain);

    string plain;
    plain = "Nam Anh";
    
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
 
	return 0;
}



