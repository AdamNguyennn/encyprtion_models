#include "functions-header.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashVerificationFilter;
// using CryptoPP::Redirector;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;
using CryptoPP::HashFilter;

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/md5.h"

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

//TODO
#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
// using CryptoPP::FileSink;

// all modes: ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM.
#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

string sha1_digest(std::string text){
    string encoded;
    SHA1 sha1;
    encoded.clear();
    StringSource s1(text, true, new HashFilter(sha1, new HexEncoder(new StringSink(encoded))));
    return encoded;
}
string md5(std::string plain) {
    byte digest[ CryptoPP::Weak::MD5::DIGESTSIZE ];
    
    CryptoPP::Weak::MD5 hash;
    hash.CalculateDigest( digest, (const byte*)plain.c_str(), plain.length() );
    
    CryptoPP::HexEncoder encoder;
    string output;
    
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();
    
    return output;
}
string PrettyPrint(byte arr[], int arraySize) {
    string encoded = "";
    encoded.clear();
    StringSource(arr, arraySize, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}
string PrettyPrint(string text) {
    string encoded = "";
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}
string HMAC_SHA_1(string text, byte key[], int keySize) {
    string mac = "";
    try
    {
        HMAC< SHA1 > hmac(key, keySize);
        StringSource(text, true, new HashFilter(hmac, new StringSink(mac)));
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return PrettyPrint(mac);
                     
}

//**************************CBC mode processing*************************
string CBCMode_Encrypt(string text, byte key[], int keySize, byte iv[]) {
    string cipher = "";
    //Encryption
    try
    {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);
        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}
string CBCMode_Decrypt(string text, byte key[], int keySize, byte iv[]) {
    string recovered = "";
    //Decryption
    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);
        StringSource s(text, true, new StreamTransformationFilter(d,new StringSink(recovered))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
} 

//**************************CFB mode processing*************************
string CFBMode_Encrypt(string text, byte key[], int keySize, byte iv[]) {
    string cipher = "";
    //Encryption
    try
    {
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);
        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}

string CFBMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
    string recovered = "";
    //Decryption
    try
    {
        CFB_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);
        StringSource s(cipher, true, new StreamTransformationFilter(d,new StringSink(recovered))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
}

//**************************ECB mode processing*************************
string ECBMode_Encrypt(string text, byte key[], int keySize) {
    string cipher = "";
    //Encryption
    try
    {
        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, keySize);
        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}

string ECBMode_Decrypt(string cipher, byte key[], int keySize) {
    string recovered = "";
    //Decryption
    try
    {
        ECB_Mode< AES >::Decryption d;
        d.SetKey(key, keySize);
        StringSource s(cipher, true, new StreamTransformationFilter(d,new StringSink(recovered))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
}

//**************************OFB mode processing*************************
// string OFBMode_Encrypt(string text, byte key[], int keySize, byte iv[]) {
//     string cipher = "";
//     //Encryption
//     try
//     {
//         OFB_Mode<AES>::Encryption e;
//         e.SetKeyWithIV(key, keySize, iv);
//         StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
//     }
//     catch(const CryptoPP::Exception& e)
//     {
//         cerr << e.what() << endl;
//         exit(1);
//     }
//     return cipher;
// }
// string OFBMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
//     string recovered = "";
//     //Decryption
//     try
//     {
//         OFB_Mode< AES >::Decryption d;
//         d.SetKeyWithIV(key, keySize, iv);
//         StringSource s(cipher, true, new StreamTransformationFilter(d,new StringSink(recovered))); // StringSource
//     }
//     catch(const CryptoPP::Exception& e)
//     {
//         cerr << e.what() << endl;
//         exit(1);
//     }
//     return recovered;
// }