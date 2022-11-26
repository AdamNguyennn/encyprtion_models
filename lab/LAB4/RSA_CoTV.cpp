/* C++ library */
#include<iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <sstream>
#include <string>
using std::string;
using std::wstring;

/* CryptoPP library */
#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;

#include "cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
// using CryptoPP::byte;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

//Genererate keys
#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

//Reading key input from file
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

// RSA cipher
#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::InvertibleRSAFunction;

/* Set location */ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

//Function definition
/* convert string to wstring */
wstring string_to_wstring (const std::string& str);

/* convert wstring to string */
string wstring_to_string (const std::wstring& str);

/* convert integer to string */
string integer_to_string(const CryptoPP::Integer& t);

/* convert integer to wstring */
wstring integer_to_wstring(const CryptoPP::Integer& t);

/* Get input  */
string GetInput(int is);

/* Save to some file */
void savefile (string input)
{
	
	wcout<<"filename: ";        // Get filename
	string filename;
	wstring wf;
    wcin>> wf;
	filename = wstring_to_string(wf);
	StringSource s(input, true, new FileSink(filename.c_str()));    // save to file
}

/* Decode key from file */
void DecodePrivateKey(const string& filename, RSA::PrivateKey& key);
void DecodePublicKey(const string& filename, RSA::PublicKey& key);
void Decode(const string& filename, BufferedTransformation& bt);

int main()
{
    // setup mode hệ điều hành
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    /* Set key auto for demo */
    AutoSeededRandomPool prng;
    // InvertibleRSAFunction params;
    // params.GenerateRandomWithKeySize(prng,3072);
    RSA::PrivateKey rsaPrivate;
    RSA::PublicKey rsaPublic;
    // Integer SK=rsaPrivate.GetPrivateExponent();
    // Integer PK=rsaPublic.GetPublicExponent();
    string fileprivate,filepublic;
    wstring temp, temp1;

    int ia, is;
    wcout << "Action: 1.Encrypt 2.Decrypt\n";
    wcin >> ia;

    wcout << "Filename private key: ";
    wcin >> temp;
    fileprivate = wstring_to_string(temp);
    wcout << "File name public key: ";
    wcin >> temp1;
    filepublic = wstring_to_string(temp1);
    DecodePrivateKey(fileprivate.c_str(), rsaPrivate);
    DecodePublicKey(filepublic.c_str(), rsaPublic);


    wcout << "Source input: 1.Screen 2.File\n";
    wcin >> is;
    switch (ia)
    {
    case 1:
    {
        string plain, cipher;
        plain = GetInput(is);

        RSAES_OAEP_SHA_Encryptor e(rsaPublic);
        StringSource ss1(plain, true,
        new PK_EncryptorFilter(prng, e,
              new Base64Encoder(
                 new StringSink(cipher)
              ) // Base64Encode
            ) // PK_EncryptorFilter
        ); // StringSource

        wcout << "cipher: " << string_to_wstring(cipher) << endl;
        // Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(cipher);
    }break;
    
    default:
    {
        string cipher, decoded, recorvered;
        cipher = GetInput(is);
        StringSource(cipher,true,new Base64Decoder(new StringSink(decoded)));

        RSAES_OAEP_SHA_Decryptor d(rsaPrivate);
        StringSource ss2(decoded, true,
        new PK_DecryptorFilter(prng, d,
            new StringSink(recorvered)
            ) // PK_DecryptorFilter
        ); // StringSource

        wcout << "recorver: " << string_to_wstring(recorvered) << endl;
        // Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recorvered);
    }break;
    }
}

//Function definition
/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t> > towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t> > tostring;
    return tostring.to_bytes(str);
}

/* convert integer to string */
string integer_to_string(const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    return encoded;
}

/* convert integer to wstring */
wstring integer_to_wstring(const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}

string GetInput(int is)
{
    wstring winput;
    string input;
    switch (is)
    {
    case 1:
    {
        wcout << "Please input: ";
        fflush(stdin);
        getline(wcin,winput);   // getline lần 1
        wcin.ignore();
        input = wstring_to_string(winput);
        return input;
    }
    
    default:
    {
        wcout << "Please filename: ";
        wcin >> winput;
        string filename = wstring_to_string(winput);
        FileSource file(filename.c_str(), true, new StringSink(input));
        return input;
    }
    }
}

void DecodePrivateKey(const string& filename, RSA::PrivateKey& key)
{
	ByteQueue queue;

	Decode(filename, queue);
	key.BERDecodePrivateKey(queue, false, queue.MaxRetrievable());
}

void DecodePublicKey(const string& filename, RSA::PublicKey& key)
{
	ByteQueue queue;

	Decode(filename, queue);
	key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
}

void Decode(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true);

	file.TransferTo(bt);
	bt.MessageEnd();
}