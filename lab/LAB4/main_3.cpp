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


#include <string>
using std::string;
using std::wstring;

#include <sstream>

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

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

//Function definition
/* convert string to wstring */
wstring string_to_wstring (const std::string& str);

/* convert wstring to string */
string wstring_to_string (const std::wstring& str);

/* convert integer to string */
string integer_to_string(const CryptoPP::Integer& t);

/* convert integer to wstring */
wstring integer_to_wstring(const CryptoPP::Integer& t);

int main(int argc, char* argv[])
{
    // setup mode hệ điều hành
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    AutoSeededRandomPool prng;
    Integer p, q, g;
    PrimeAndGenerator pg;
    pg.Generate(1, prng, 512, 511);
    p = pg.Prime();
    q = pg.SubPrime();
    g = pg.Generator();
    // cout << "p: " << p << endl;
    // cout << "q: " << q << endl;
    // cout << "g: " << g << endl;

    // ModularArithmetic ma(p); 
    // Integer x("5738592352534556747104289660421262539500678100766128832735.");
    // Integer y("8563265737285361724904289660421262539500678100766128765412.");
    // Integer x1(ma.Divide(1, x));

    // cout << "x+y mod p: " << ma.Add(x, y) << endl;
    // cout << "x-y mod p: " << ma.Subtract(x, y) << endl;
    // cout << "x*y mod p: " << ma.Multiply(x, y) << endl;
    // cout << "x/y mod p: " << ma.Divide(x, y) << endl;
    // cout << "x%y mod p: " << ma.Reduce(x, y) << endl;
    // cout << "x^y mod p: " << ma.Exponentiate(x, y) << endl;
    // cout << "x1=x^-1 mod p: " << x1 << endl;
    // cout << "x*x1 mod p: " << ma.Multiply(x, x1) << endl;

    ModularArithmetic ma(p); // mod p
    Integer x("1958569211444031162104289660421262539500678100766128832735.");
    Integer y("2858569211444031162104289660421262539500678100766128765412.");

    // cout << "a = " << a << endl;
    // cout << "b = " << b << endl;
    // cout << "c = " << c << endl;
    // cout << "d = " << d << endl;
    // cout << "e = " << e << endl;
    // cout << "x = " << x << endl;
    // string csrip = "Code hỗ trợ tiếng việt";
    // wcout << string_to_wstring(csrip) << endl;
    // wcout << "prime number p = " << integer_to_wstring(p) << endl;
    // wcout << "prime number q = " << integer_to_wstring(q) << endl;
    // wcout << "generator number g = " << integer_to_wstring(g) << endl;

    // cout << "x+y mod p: " << ma.Add(x, y) << endl;
    // cout << "x-y mod p: " << ma.Subtract(x, y) << endl;
    // cout << "x*y mod p: " << ma.Multiply(x, y) << endl;
    // cout << "x/y mod p: " << ma.Divide(x, y) << endl;
    // cout << "x%y mod p: " << ma.Reduce(x, y) << endl;
    // cout << "x^y mod p: " << ma.Exponentiate(x, y) << endl;
    // Integer x1(ma.Divide(1, x));
    // cout << "x1=x^-1 mod p: " <<ma.Divide(1, x) << endl;
    // cout << "x*x1 mod p: " << ma.Multiply(x, x1) << endl;

    // wcout <<"x*y mod p: " <<  integer_to_wstring(a_times_b_mod_c(x,y,p)) << endl;
    // wcout <<"x/y mod p: " <<  integer_to_wstring(a_exp_b_mod_c(x,y,p)) << endl;

    // Convert wstring to integer
    // wstring ss; 
    // string encode;
    // wcout << "Input message: ";
    // getline(wcin,ss);
    // encode.clear();
    // StringSource(wstring_to_string(ss),true,new HexEncoder(new StringSink(encode)));
    // encode +="H";
    // wcout<< "string to hex: " << string_to_wstring(encode) << endl;
    // Integer h(encode.data());
    // wcout << "wstring to number h: " << integer_to_wstring(h) << endl;

    // Convert integer to wstring
    wstring ss; 
    string encode;
    ss.clear();
    string decode;
    wcout << "Input integer: ";
    getline(wcin,ss);
    decode.clear();
    Integer h(wstring_to_string(ss).data());
    encode = integer_to_string(h);
    StringSource(encode,true,new HexDecoder(new StringSink(decode)));
    wcout << string_to_wstring(decode);

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