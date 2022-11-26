#include<iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

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

#include <sstream>

#include <string>
using std::string;
using std::wstring;

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

#include "cryptopp/files.h"
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

/*Reading key input from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

/* RSA cipher*/
#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;
using CryptoPP::InvertibleRSAFunction;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

//Function definition
/* convert string to wstring */
wstring string_to_wstring (const std::string& str);

/* convert wstring to string */
string wstring_to_string (const std::wstring& str);

/* convert integer to string */
string integer_to_string(const CryptoPP::Integer& t);

/* convert integer to wstring */
wstring integer_to_wstring(const CryptoPP::Integer& t);

void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key);
void EncodePublicKey(const string& filename, const RSA::PublicKey& key);
void Encode(const string& filename, const BufferedTransformation& bt);

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

    AutoSeededRandomPool rng;
    // RSA::PrivateKey rsaPrivate;
    // RSA::PublicKey rsaPublic;
    // Integer q,p,n,e,d,phi;
    // InvertibleRSAFunction rsa;
    
    // PrimeAndGenerator pg,pgg;
    // pg.Generate(-1, prng, 1024, 1023);   
    // p = pg.Prime();
    // q = pg.SubPrime();
    // n = p*q;
    // phi = (p-1)*(q-1);
    // pg.Generate(-1, prng, 3072, 3071);
    // e = pg.Prime();
    // ModularArithmetic ma(phi);
    // d = ma.Divide(1, e);
    // rsaPrivate.Initialize(n, e, d);
    // rsaPublic.Initialize(n, e);
    // rsa.SetModulus(n);
    // rsa.SetPrivateExponent(d);
    // rsa.SetPrime1(p);
    // rsa.SetPrime2(q);
    // // add this:
    // rsa.SetModPrime1PrivateExponent( d % (p-1) );
    // rsa.SetModPrime2PrivateExponent( d % (q-1) );
    // rsa.SetMultiplicativeInverseOfPrime2ModPrime1( q.InverseMod(p) );
    // rsa.SetPublicExponent( d.InverseMod((p-1) * (q-1)) );
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 3072);

    RSA::PrivateKey rsaPrivate(params);
    RSA::PublicKey rsaPublic(params);
    
    EncodePrivateKey("./keys/rsa-private.key", rsaPrivate);
	EncodePublicKey("./keys/rsa-public.key", rsaPublic);
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

void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
	ByteQueue queue;
	key.DEREncodePrivateKey(queue);

	Encode(filename, queue);
}

void EncodePublicKey(const string& filename, const RSA::PublicKey& key)
{
	ByteQueue queue;
	key.DEREncodePublicKey(queue);

	Encode(filename, queue);
}

void Encode(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}