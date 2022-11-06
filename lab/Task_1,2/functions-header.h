#ifndef FUNCTIONS_H_INCLUDED
#define FUNCTIONS_H_INCLUDED

std::string sha1_digest(std::string text);
std::string md5(std::string text);

std::string PrettyPrint(byte arr[], int arraySize);
std::string PrettyPrint(std::string text);
std::string HMAC_SHA_1(std::string text, byte key[], int keySize);
std::string ECBMode_Encrypt(std::string text, byte key[], int keySize);
std::string ECBMode_Decrypt(std::string text, byte key[], int keySize);

// CBC
std::string CBCMode_Encrypt(std::string text, byte key[], int keySize);
std::string CBCMode_Decrypt(std::string text, byte key[], int keySize);
#endif