//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"

#include <ctime>
#include <iostream>
#include <string>
using namespace std;

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

int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;
// Contruct standrad curve from OID
    /* ECC curve */
    CryptoPP::OID oid= ASN1::secp256r1();
    /* Create a curve for ECDH*/ 
    CryptoPP::ECDH<ECP>::Domain ecdh(oid);
    /* Create key pairs*/
    CryptoPP::SecByteBlock privKey(ecdh.PrivateKeyLength()), pubKey(ecdh.PublicKeyLength());
    ecdh.GenerateKeyPair(rng, privKey, pubKey);
    //hex incode
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(cout));
    cout << "Private key: ";
    encoder.Put(privKey, privKey.size());
    cout << endl;
    cout << "Public key: ";
    encoder.Put(pubKey, pubKey.size());
    cout << endl; 
        
        CryptoPP::DL_GroupParameters_EC<ECP> curve256;
        curve256.Initialize(oid);
        /* Get Curve parameters p, a,b, G, n, h*/
        ECP::Point G=curve256.GetSubgroupGenerator(); // Get Base point G
        cout << "Gx=" <<G.x << endl;
        cout << "Gy=" << G.y << endl;
        CryptoPP::Integer n=curve256.GetSubgroupOrder(); // Get order n
        cout << "n=" << n << endl;
        CryptoPP::Integer h=curve256.GetCofactor();  // Get Cofactor h    
        cout << "Cofactor h=" << h << endl;
        CryptoPP::Integer a=curve256.GetCurve().GetA(); //Get Coefficient a 
        cout << "Coefficient a=" << a << endl; 
        CryptoPP::Integer b=curve256.GetCurve().GetB(); //Get Coefficient b 
        cout << "Coefficient b=" << b << endl;
        /* Curve operations*/
        /* Compute on subgroup <G> */
        ECP::Point  Q=curve256.GetCurve().Double(G);
        cout << "Qx=" << Q.x << endl;
        cout << "Qy=" << Q.y << endl;
        // Scalar Multiply
        CryptoPP::Integer k("871.");
        ECP::Point U=curve256.GetCurve().Multiply(k,G);
        cout << "Ux=" << U.x << endl;
        cout << "Uy=" << U.y << endl;
        // Point Addition
        ECP::Point V=curve256.GetCurve().Add(Q,U);
        cout << "Vx=" << U.x << endl;
        cout << "Vy=" << U.y << endl;
         // Point invertion
        ECP::Point X=curve256.GetCurve().Inverse(G);
        cout << "Xx=" << X.x << endl;
        cout << "Xy=" << X.y << endl;
        // Multiple
        ECP::Point H=curve256.GetCurve().ScalarMultiply(G,k);
        cout << "Hx=" << H.x << endl;
        cout << "Hy=" << H.y << endl;
}