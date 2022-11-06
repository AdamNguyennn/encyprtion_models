#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "functions.h"
using namespace std;

int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;
    //Define the key and iv
    byte iv[AES::BLOCKSIZE];
    byte key[32], fkey[32];

    // Create random iv
    prng.GenerateBlock(iv, sizeof(iv));
    
    // Create random key
    prng.GenerateBlock(fkey, sizeof(fkey));
    // Write key to file
	StringSource ss(fkey, sizeof(fkey), true , new FileSink( "AES_key.key"));
    
    /* Reading key from file*/
	FileSource fs("AES_key.key", false);
    /*Create space  for key*/ 
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data from AES_key.key  to  key */ 
	fs.Detach(new Redirector(copykey));
	fs.Pump(sizeof(key));  // Pump first 32 bytes
    
    
    
    string plain;
    cout << "Insert plain text: ";
    // cin >> plain;
    getline(cin, plain);

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

