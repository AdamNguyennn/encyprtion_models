#include<iostream>
using namespace std;
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;
#include <string>
using std::string;
using std::wstring;
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#include <assert.h>

/* Filters */
#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

/* File */
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;


#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;

#include "cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;


/* standard curves*/
#include "cryptopp/nbtheory.h"
#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECIES;
using CryptoPP::ECDSA;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

/* Curve */
#include "cryptopp/asn.h"
#include "cryptopp/oids.h" 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

void LoadPrivateKey( const string& filename, CryptoPP::ECDSA<ECP, SHA256>::PrivateKey& key );
void LoadPublicKey( const string& filename, CryptoPP::ECDSA<ECP, SHA256>::PublicKey& key );
wstring s2ws(const std::string &str);
string ws2s(const std::wstring &str);
bool SignMessage( const CryptoPP::ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const CryptoPP::ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature );

string dataa;            
string signature;
CryptoPP::ECDSA<ECP, SHA256>::PrivateKey privateKey;
CryptoPP::ECDSA<ECP, SHA256>::PublicKey publicKey;

int main()
{
    #ifdef __linux__
	setlocale(LC_ALL, "");
    #elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif
  
    int ia;
    wcout << "Action: 1.Sigh 2.Verify\n";
    wcin >> ia;

    // wstring temp, temp1;
    // string fileprivate, filepublic;
    // wcout << "Filename private key: ";
    // wcin >> temp;
    // fileprivate = ws2s(temp);
    // wcout << "File name public key: ";
    // wcin >> temp1;
    // filepublic = ws2s(temp1);
    LoadPrivateKey("ec.private.key", privateKey);
    LoadPublicKey("ec.public.key", publicKey);

    switch (ia)
    {
        case 1:
        {
            wstring wfilename;
            string filename;
            bool result = false;

            // wcout << "Filename need sigh: ";
            // wcin >>  wfilename;
            // filename = ws2s(wfilename);
            FileSource fpl("text.txt", true, new StringSink(dataa));
            result = SignMessage( privateKey, dataa, signature );
            assert( true == result );

            // wcout <<"File name save signature: ";
            // wcin >>  wfilename;
            // filename = ws2s(wfilename);
            StringSource s(signature, true, new FileSink("sigh.txt"));
        }break;

        default:
        {
            wstring wfilename;
            string filename;
            bool result = false;

            // wcout << "Filename need verify: ";
            // wcin >>  wfilename;
            // filename = ws2s(wfilename);
            FileSource fpl("text.txt", true, new StringSink(dataa));
            // wcout << "filename of signature: ";
            // wcin >> wfilename;
            // filename = ws2s(wfilename);
            FileSource fpll("sigh.txt", true, new StringSink(signature));

            result = VerifyMessage( publicKey, dataa, signature );
            assert( true == result );
            
            if(result) wcout << "Great";
            else wcout << "Something wrong";
        }break;
    }

}
/* convert string to wstring */
wstring s2ws(const std::string &str)
{
	wstring_convert<codecvt_utf8<wchar_t>> towstring;
	return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const std::wstring &str)
{
	wstring_convert<codecvt_utf8<wchar_t>> tostring;
	return tostring.to_bytes(str);
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA256>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    double sum =0.0;

    signature.erase();    
    for(int i=1;i<=10000;i++)
    {
        signature.erase();
        auto start = std::chrono::high_resolution_clock::now();
        StringSource( message, true,
            new SignerFilter( prng,
                ECDSA<ECP,SHA256>::Signer(key),
                new StringSink( signature )
            ) // SignerFilter
        ); // StringSource
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> float_ms = end - start; // milliseconds
        sum+= float_ms.count();
    }
    wcout << "[-] Average time taken for sigh: " << double(sum / 10000) << " miliseconds" << endl;
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;
    double sum =0.0;

    for(int i=1;i<=10000;i++)
    {
        result = false;
        auto start = std::chrono::high_resolution_clock::now();
        StringSource( signature+message, true,
            new SignatureVerificationFilter(
                ECDSA<ECP,SHA256>::Verifier(key),
                new ArraySink( (CryptoPP::byte*)&result, sizeof(result) )
            ) // SignatureVerificationFilter
        );
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> float_ms = end - start; // milliseconds
        sum+= float_ms.count();
    }
    wcout << "[-] Average time taken for verify: " << double(sum / 10000) << " miliseconds" << endl;

    return result;
}