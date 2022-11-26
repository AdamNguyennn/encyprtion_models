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
// WINDOWS
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
// LINUX
#ifdef __linux__
setlocale(LC_ALL,"");
#elif _WIN32
_setmode(_fileno(stdin), _O_U16TEXT);
_setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
//////////////////////

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


/*External library*/
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;


#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector; // string to bytes

// Get plaintext or ciphertext
void Getinput()
{
    // Get input
	int ci;
	wcout<<"Choose input modes: ";
    wcout<<"\t\t1.Input from screen";
    wcout<<"\t\t2.Input from file";
	wcin>>ci;
	fflush(stdin);
	wstring wplain;
	switch (ci)
	{
	case 1:
	{
        wcout<<"Input plain text: ";
        getline(wcin,wplain);          // First getline
		fflush(stdin);
        plain = wstring_to_string(wplain);
	}break;
	case 2:
	 { 
        string filename;
		wstring wf;
        wcout<<"Input filename: ";  //get filename to string
		wcin>>wf;
		filename = wstring_to_string(wf);
	    FileSource file(filename.c_str(), true, new StringSink(plain));  // put cipher or plain in plain variable
	 }break;
	default:
	{}break;
	}
}

int generate_key()
{
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 3072);

    RSA::PrivateKey rsaPrivate(params);
    RSA::PublicKey rsaPublic(params);
    
    EncodePrivateKey("./keys/rsa-private.key", rsaPrivate);
	EncodePublicKey("./keys/rsa-public.key", rsaPublic);
}


// Get key, iv, nan
void GetMaterial(int c=0)
{
    switch (c)
    {
    case 0:  // Cho các mode có dùng iv và key: CBC, OFB, CFB, CTR, CCM, GCM
    {
		// Giao diện 
        wcout<<"Chon nguon key va iv/nan: 1.Random 2.Screen 3.File\n";
        int ikv;
	    wcin>>ikv;
        switch (ikv)
        {
        case 1: 
        {
            // iv/nan, key tự sinh
            AutoSeededRandomPool prng;
		    prng.GenerateBlock(key, sizeof(key));
		    prng.GenerateBlock(iv, sizeof(iv));
        }break;
        case 2:
        {
            // iv, key từ màng hình
	        wcout<<"Please key: ";        // key nhập từ màng hình sẽ ở dạng hex
		    wstring wskey;
	        wcin>>wskey;         
	        string skey = wstring_to_string(wskey);
	        StringSource(skey,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
			
			wcout<<"Please iv/nan: ";         // iv/nan nhập từ màng hình sẽ ở dạng hex 
		    wstring wiv;
	        wcin>>wiv;       
	        string siv = wstring_to_string(wiv);
	        StringSource(siv,true,new HexDecoder( new CryptoPP::ArraySink(iv,sizeof(iv))));
        }break;
        case 3:
        {
            // iv, key từ file
			// get key 
            wcout<<"Please key filename: ";         // Lấy tên file chứa key
            string filekey, hexkey;
			wstring wk;
            wcin>>wk;
			filekey = wstring_to_string(wk);
			// key được lưu ở dạng hex trong file nên cần decode trước khi gán vào key variable
	        FileSource fs(filekey.c_str(), true,new HexDecoder( new CryptoPP::ArraySink(key, sizeof(key))));;
			
			// get iv
            wcout<<"Please iv/nan filename: ";          // Lấy tên file chứa iv
            string fileiv;
			wstring wi;
            wcin>>wi;
			fileiv = wstring_to_string(wi);
			// iv được lưu ở dạng hex trong file nên cần decode trước khi gán vào iv variable
			FileSource fss(fileiv.c_str(), true,new HexDecoder( new CryptoPP::ArraySink(iv, sizeof(iv))));
        }
        default:
            break;
        }
    }break;
    case 1: // Cho mode ECB 
    {
        wcout<<"Chon nguon key : 1.Random 2.Screen 3.File\n";
        int ikv;
	    wcin>>ikv;
        switch (ikv)
        {
        case 1: 
        {
            // key tự sinh
            AutoSeededRandomPool prng;
		    prng.GenerateBlock(key, sizeof(key));
        }break;
        case 2:
        {
            // key từ màng hình
	        wcout<<"Please key: ";
		    wstring wskey;
		    fflush(stdin);
	        getline(wcin,wskey);         // Second getline
	        string skey = wstring_to_string(wskey);
	        StringSource(skey,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
        }break;
        case 3:
        {
            // key từ file
            wcout<<"Please key filename: ";   // Lấy tên file chứa key
            string filekey;
			wstring wk;
            wcin>> wk;
			filekey = wstring_to_string(wk);
            // key được lưu ở dạng hex trong file nên cần decode trước khi gán vào key variable
	        FileSource fs(filekey.c_str(), true,new HexDecoder( new CryptoPP::ArraySink(key, sizeof(key))));;
        }
        default:
            break;
        }   
    }break;
    default:
        break;
    }
}

// Show giá trị của key, iv, nan ở dạng hex
void Display(int i=0)
{
	if(i==0)      // Cho các mode có dùng iv và key: CBC, OFB, CFB, CTR, CCM, GCM
	{
		encoded.clear();
	    StringSource(key, sizeof(key), true,
		    new HexEncoder(
			    new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	    encoded.clear();
	    StringSource(iv, sizeof(iv), true,
		    new HexEncoder(
			    new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;
	}
	else      // Cho mode ECB chỉ dùng đến key
	{
		encoded.clear();
	    StringSource(key, sizeof(key), true,
		    new HexEncoder(
			    new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;
	}
}

// Save to some file
void savefile (string input)
{
	
	wcout<<"filename: ";        // Get filename
	string filename;
	wstring wf;
    wcin>> wf;
	filename = wstring_to_string(wf);
	StringSource s(input, true, new FileSink(filename.c_str()));    // save to file
}

int ia;
void M_ECB();
void M_CBC();
void M_OFB();
void M_CFB();
void M_CTR();
void M_XTS();
void M_CCM();
void M_GCM();

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
	wcout<<"*********************************" << endl << "               AES\n" << "*********************************\n";
    // Lấy mode (từ màng hình)
	wcout<<"Please mode: 1.ECB 2.CBC 3.OFB 4.CFB 5.CTR 6.XTS 7.CCM 8.GCM\n";
	int im;
	wcin>>im;
    // Lấy hoạt động (từ màng hình)
    wcout<<"Please action: 1.Encypt 2.Decrypt\n";
    wcin>>ia;
    // Gọi mode
    switch (im)
    {
        case 1:
        {
            M_ECB();
        }break;
        case 2:
        {
            M_CBC();
        }break;
        case 3:
        {
            M_OFB();
        }break;
        case 4:
        {
            M_CFB();
        }break;
        case 5:
        {
            M_CTR();
        }break;
        case 6:
        {
            M_XTS();
        }break;
        case 7:
        {
            M_CCM();
        }break;
        case 8:
        {
            M_GCM();
        }break;
        default:
        {}break;
    }

}

// ECB 
void M_ECB()
{
	// prepare
    Getinput();
    GetMaterial(1);
	Display(1);

    switch (ia)
    {
    case 1:   // Encrypt
    {
        try
		{
		    ECB_Mode< AES >::Encryption e;
		    e.SetKey(key, sizeof(key));
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
        // Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		
		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:    //Decrypt
    {
        try 
        {
        StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
        ECB_Mode< AES >::Decryption d;
		   d.SetKey(key, sizeof(key));
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        // Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
    }break;
    default:
        break;
    }
}

// CBC
void M_CBC()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:    // Encrypt
    {
        try
		{
		    CBC_Mode< AES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:     // Decrypt
    {
        try 
        {
            StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
            CBC_Mode< AES >::Decryption d;
		    d.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        // Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
    }break;
    default:
        break;
    }
}

// OFB
void M_OFB()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:    // Encrypt
    {
        try
		{
		    OFB_Mode< AES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:    // Decrypt
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   OFB_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
    }break;
    default:
        break;
    }
}

// CFB
void M_CFB()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:    // Encrypt
    {
        try
		{
		    CFB_Mode< AES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:    // Decrypt
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CFB_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
    }break;
    default:
        break;
    }
}

//CTR
void M_CTR()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:
    {
        try
		{
		    CTR_Mode< AES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CTR_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
    }
    default:
        break;
    }
}

// XTS
void M_XTS()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:
    {
        try
		{
		    XTS_Mode< AES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
        wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   XTS_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
    }break;
    default:
        break;
    }
}

// CCM
void M_CCM()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:
    {
        try
        {
			CCM< AES, 12 >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    e.SpecifyDataLengths( 0, plain.size(), 0 );
		    StringSource s(plain, true, 
			   new AuthenticatedEncryptionFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CCM< AES, 12 >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   d.SpecifyDataLengths( 0, cipher.size() - 12, 0 );
		   AuthenticatedDecryptionFilter df( d,
           new StringSink( recovered));
		   StringSource s(cipher, true, 
			   new Redirector(df));
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
    }break;
    default:
        break;
    }
}

// GCM
void M_GCM()
{
	//prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:
    {
        try
		{
		    GCM< AES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new AuthenticatedEncryptionFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:
    {
        try
	    {
		   StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   GCM< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			new AuthenticatedDecryptionFilter(d,
				new StringSink(recovered)
			) 
		); 
		// Pretty print plain
		wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(recovered);
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
    }break;
    default:
        break;
    }
}


////////////// UTILITIES FUNCTION //////////////
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