//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"

#include <ctime>
#include <iostream>
#include <string>
using namespace std;

#include "cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;

/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;    // Prime field p
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;
// hex convert
#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
// File operation
#include <cryptopp/files.h>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

/* convert integer to string */
string integer_to_string(const CryptoPP::Integer& t);

int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;
// Contruct standrad curve from OID
    /* ECC curve */
    CryptoPP::OID oid= ASN1::secp256r1();
    /* Create a curve for ECDH*/ 
    CryptoPP::ECDH<ECP>::Domain ecdh(oid);
    /* Create key pairs*/
    CryptoPP::SecByteBlock privKey_1(ecdh.PrivateKeyLength()), pubKey_1(ecdh.PublicKeyLength());
    CryptoPP::SecByteBlock privKey_2(ecdh.PrivateKeyLength()), pubKey_2(ecdh.PublicKeyLength());
    // ecdh.GenerateKeyPair(rng, privKey, pubKey);
    //hex incode
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(cout));
    cout << "Private key 1: ";
    encoder.Put(privKey_1, privKey_1.size());
    cout << endl;
    cout << "Public key 1: ";
    encoder.Put(pubKey_1, pubKey_1.size());
    cout << endl;
    cout << "Private key 2: ";
    encoder.Put(privKey_2, privKey_2.size());
    cout << endl;
    cout << "Public key 2: ";
    encoder.Put(pubKey_2, pubKey_2.size());
    cout << endl;
    PrimeAndGenerator pg;
    pg.Generate(1, rng, 512, 511);
    cout<< "Prime: " << pg.Prime();
    cout << endl; 
        // // Curve 256
        // CryptoPP::DL_GroupParameters_EC<ECP> curve384;
        // curve384.Initialize(oid);
        // /* Get Curve parameters p, a,b, G, n, h*/
        // ECP::Point G=curve384.GetSubgroupGenerator(); // Get Base point G
        // cout << "Base point G(x,y)" << endl;
        // cout << "Gx=" <<G.x << endl;
        // cout << "Gy=" << G.y << endl;
        // CryptoPP::Integer n=curve384.GetSubgroupOrder(); // Get order n
        // cout << "Number of curve point" << endl;
        // cout << "n=" << n << endl;
        // CryptoPP::Integer h=curve384.GetCofactor();  // Get Cofactor h    
        // cout << "Cofactor h=" << h << endl;
        // CryptoPP::Integer a=curve384.GetCurve().GetA(); //Get Coefficient a 
        // cout << "Coefficient a=" << a << endl; 
        // CryptoPP::Integer b=curve384.GetCurve().GetB(); //Get Coefficient b 
        // cout << "Coefficient b=" << b << endl;
        // /* Curve operations*/
        // /* Compute on subgroup <G> */
        // ECP::Point  Q=curve384.GetCurve().Double(G);
        // cout << "Curve point Q=G+G" << endl;
        // cout << "Qx=" << Q.x << endl;
        // cout << "Qy=" << Q.y << endl;
        // // Scalar Multiply
        // CryptoPP::Integer k("871.");
        // ECP::Point U=curve384.GetCurve().Multiply(k,G);
        // cout << "Curve point U = 871*G" << endl;
        // cout << "Ux=" << U.x << endl;
        // cout << "Uy=" << U.y << endl;
        // // Point Addition
        // ECP::Point V=curve384.GetCurve().Add(Q,U);
        // cout << "Curve point V = Q+U" << endl;
        // cout << "Vx=" << U.x << endl;
        // cout << "Vy=" << U.y << endl;
        //  // Point invertion
        // ECP::Point X=curve384.GetCurve().Inverse(G);
        // cout << "Curve point X = G^-1" << endl;
        // cout << "Xx=" << X.x << endl;
        // cout << "Xy=" << X.y << endl;
        // // Multiple
        // ECP::Point H=curve384.GetCurve().ScalarMultiply(G,k);
        // cout << "Curve point H = 871*G" << endl;
        // cout << "Hx=" << H.x << endl;
        // cout << "Hy=" << H.y << endl;

    PrimeAndGenerator d1, d2;
    d1.Generate(1, rng, 512, 511);
    d2.Generate(1, rng, 512, 511);
    cout<< "Prime_1: " << d1.Prime();
    cout << endl;
    cout<< "Prime_2: " << d2.Prime();
    cout << endl;
    // Curve 256
    CryptoPP::DL_GroupParameters_EC<ECP> curve384;
    curve384.Initialize(oid);
    /* Get Curve parameters p, a,b, G, n, h*/
    ECP::Point G=curve384.GetSubgroupGenerator(); // Get Base point G
    cout << "Base point G(x,y)" << endl;
    cout << "Gx=" <<G.x << endl;
    cout << "Gy=" << G.y << endl;
    CryptoPP::Integer k1(d1);
    ECP::Point Q1=curve384.GetCurve().Multiply(k1,G);
    cout << "Q1 = d1*G" << endl;
    cout << "Q1_x=" << U.x << endl;
    cout << "Q1_y=" << U.y << endl;
    CryptoPP::Integer k2(d2);
    ECP::Point Q2=curve384.GetCurve().Multiply(k2,G);
    cout << "Q2 = d2*G" << endl;
    cout << "Q2_x=" << U.x << endl;
    cout << "Q2_y=" << U.y << endl;

    // OID CURVE = secp256r1();
    // ECDH < ECP >::Domain dhA( CURVE ), dhB( CURVE );
    // SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    // SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());
    // CryptoPP::Integer Qx_1(Q1.x);
    // CryptoPP::Integer Qy_1(Q1.y);
    // CryptoPP::Integer Qx_2(Q2.x);
    // CryptoPP::Integer Qy_2(Q2.y);

    // dhA.GenerateKeyPair(rng, Qx_1, Qy_1);
    // dhB.GenerateKeyPair(rng, Qx_2, Qy_2);

    // if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
	// throw runtime_error("Shared secret size mismatch");
}