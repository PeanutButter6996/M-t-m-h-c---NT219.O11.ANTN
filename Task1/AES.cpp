//C internal library 
#include <iostream>
using std::wcin;
using std::wcout;
using std::wcerr;
using std::endl;
#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
using std::exit;
#include "assert.h"

//Cryptopp Librari
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;

//Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include <cryptopp/ccm.h>
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
//Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison

//Using chrono for time measurements
#include <chrono>



/* Set utf8 support for windows*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string <--> utf8*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

using namespace std;
using namespace CryptoPP;

wstring string_to_wstring(const string& str);
string wstring_to_string(const wstring& str);


/************************Utils************************\
\*****************************************************/

void hex_to_byte(string &input)
{
    string decoded;

    StringSource(input, true,
        new HexDecoder(
            new StringSink(decoded)
        ) // HexEncoder
    ); // StringSource

    input = decoded;
}

void save_to_file_key_iv(string keyHex, string ivHex) {
    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>); // UTF-8
    std::ofstream fout("key_iv.txt");
    if (!fout){
        std::cout << "Can't output to key_iv.txt\n";
    } else {
        fout.imbue(loc);
        fout << keyHex << "\n";
        fout << ivHex << "\n";
        fout.close();
    }

    

}

void save_to_file_enc(string encryptedText) {
    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>); // UTF-8
    std::ofstream out("encrypted.txt");
    if (!out) {
        std::cout << "Can't output to encrypted.txt\n";
    } else {
        out.imbue(loc);
        out << encryptedText << endl;
        out.close();
    }
}

void save_to_file_dec(string decryptedText) {
    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>); // UTF-8
    std::ofstream out("decrypted.txt");
    if (!out) {
        std::cout << "Can't output to decrypted.txt\n";
    } else {
        out.imbue(loc);
        out << decryptedText << endl;
        out.close();
    }

}

const int TAG_SIZE = 12;

/*****************************************************\
\*****************************************************/


/************************Modes************************\
\*****************************************************/

//------------------CBC Mode------------------//
//--------------------------------------------//
string cbc_encrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // Convert input text to bytes
    string plainText = input;

    // Encrypt the text using CBC mode
    string cipherText, encodedText;
    StringSource(plainText, true, new StreamTransformationFilter(e, new StringSink(cipherText)));

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;
}

string cbc_decrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
            ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CBC Mode decryption logic
    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    string cipherText = input;
    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));

    // Decrypt the text using CBC mode
    string decryptedText;
    StringSource(decodedText, true, new StreamTransformationFilter(d, new StringSink(decryptedText)));

    return decryptedText;
}

//------------------ECB Mode------------------//
//--------------------------------------------//
string ecb_encrypt(string input, string keyHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    // ECB Mode encryption logic
    ECB_Mode<AES>::Encryption e;
    e.SetKey(key, key.size());

    // Convert input text to bytes
    string plainText = input;

    // Encrypt the text using ECB mode (no IV needed)
    string cipherText, encodedText;
    StringSource(plainText, true, new StreamTransformationFilter(e, new StringSink(cipherText)));

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;
}

string ecb_decrypt(string input, string keyHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    // ECB Mode decryption logic
    ECB_Mode<AES>::Decryption d;
    d.SetKey(key, key.size());

    // Convert input text (encrypted text) to bytes
    string cipherText = input;

    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));
    // Decrypt the text using ECB mode (no IV needed)
    string decryptedText;
    StringSource(decodedText, true, new StreamTransformationFilter(d, new StringSink(decryptedText)));

    return decryptedText;
}

//------------------CFB Mode------------------//
//--------------------------------------------//
string cfb_decrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CFB Mode decryption logic
    CFB_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    // Convert the input encrypted text (cipherText) to bytes
    string cipherText = input;

    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));

    // Decrypt the text using CFB mode
    string decryptedText;
    StringSource(decodedText, true, new StreamTransformationFilter(d, new StringSink(decryptedText)));

    return decryptedText;
}

string cfb_encrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CFB Mode encryption logic
    CFB_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // Convert input text to bytes
    string plainText = input;

    // Encrypt the text using CFB mode
    string cipherText, encodedText;
    StringSource(plainText, true, new StreamTransformationFilter(e, new StringSink(cipherText)));

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;
}

//------------------OFB Mode------------------//
//--------------------------------------------//
string ofb_encrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // OFB Mode encryption logic
    OFB_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // Convert input text to bytes
    string plainText = input;

    // Encrypt the text using OFB mode
    string cipherText, encodedText;
    StringSource(plainText, true, new StreamTransformationFilter(e, new StringSink(cipherText)));

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;
}

string ofb_decrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // OFB Mode decryption logic
    OFB_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    // Convert the input encrypted text (cipherText) to bytes
    string cipherText = input;

    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));

    // Decrypt the text using OFB mode
    string decryptedText;
    StringSource(decodedText, true, new StreamTransformationFilter(d, new StringSink(decryptedText)));

    return decryptedText;
}

//------------------CTR Mode------------------//
//--------------------------------------------//
string ctr_encrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CTR Mode encryption logic
    CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // Convert input text to bytes
    string plainText = input;

    // Encrypt the text using CTR mode
    string cipherText, encodedText;
    StringSource(plainText, true, new StreamTransformationFilter(e, new StringSink(cipherText)));

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;
}

string ctr_decrypt(string input, string keyHex, string ivHex)
{
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CTR Mode decryption logic
    CTR_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    // Convert the input encrypted text (cipherText) to bytes
    string cipherText = input;

    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));

    // Decrypt the text using CTR mode
    string decryptedText;
    StringSource(decodedText, true, new StreamTransformationFilter(d, new StringSink(decryptedText)));

    return decryptedText;
}


//------------------XTS Mode------------------//
//--------------------------------------------//
string xts_encrypt(string input, string keyHex, string ivHex){
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // XTS Mode encryption logic
    XTS_Mode< AES >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    //Convert input text to bytes
    string plainText = input;

    //Encrypt the text using XTS mode
    string cipherText, encodedText;
    StringSource ( plainText, true, 
        new StreamTransformationFilter( e,
            new StringSink( cipherText ),
            StreamTransformationFilter::NO_PADDING
        ) // StreamTransformationFilter      
    ); // StringSource

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;
}

string xts_decrypt(string input, string keyHex, string ivHex){
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    );// StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // XTS Mode decryption logic
    XTS_Mode< AES >::Decryption d;
    d.SetKeyWithIV( key, key.size(), iv );

    // Convert the input encrypted text (cipherText) to bytes
    string cipherText = input;

    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));

    // Decrypt the text using CTR mode
    string decryptedText;
    StringSource ( decodedText, true, new StreamTransformationFilter( d, new StringSink( decryptedText ),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSourc
    return decryptedText;
}


//------------------GCM Mode------------------//
//--------------------------------------------//

string gcm_encrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    );// StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    GCM< AES >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );

    //Convert input text to bytes
    string plainText = input;

    //Encrypt the text using GCM mode
    string cipherText, encodedText;
    StringSource ( plainText, true,
        new AuthenticatedEncryptionFilter( e,
            new StringSink( cipherText ), false, TAG_SIZE
        ) // AuthenticatedEncryptionFilter
    ); // StringSource

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;
}

string gcm_decrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    );// StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    GCM< AES >::Decryption d;
    d.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );

    // Convert the input encrypted text (cipherText) to bytes
    string cipherText = input;

    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));

    // Decrypt the text using CTR mode
    string decryptedText;
     AuthenticatedDecryptionFilter df( d,
        new StringSink( decryptedText ), AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE
    ); // AuthenticatedDecryptionFilter

    StringSource ( decodedText, true,
        new Redirector(df)
    ); // StringSource

    return decryptedText;
}


//------------------CCM Mode------------------//
//--------------------------------------------//

string ccm_encrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[13];

    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    );// StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    //Convert input text to bytes
    string plainText = input;

    CCM< AES, TAG_SIZE >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv);
    e.SpecifyDataLengths( 0, plainText.size(), 0 );

    
    //Encrypt the text using CCM mode
    string cipherText, encodedText;
    StringSource ( plainText, true,
        new AuthenticatedEncryptionFilter( e,
            new StringSink( cipherText )
        ) // AuthenticatedEncryptionFilter
    ); // StringSource

    StringSource(cipherText, true,
        new Base64Encoder(
            new StringSink(encodedText), false
        ) // HexEncoder
    ); // StringSource

    return encodedText;

}

string ccm_decrypt(string input, string keyHex, string ivHex) {
    hex_to_byte(keyHex);
    SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(&keyHex[0]), keyHex.size());

    string iv_string;
    CryptoPP::byte iv[13];


    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    );// StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));


    // Convert the input encrypted text (cipherText) to bytes
    string cipherText = input;
    // Decode Base64
    string decodedText;
    StringSource(cipherText, true, new Base64Decoder(new StringSink(decodedText)));

    CCM< AES, TAG_SIZE >::Decryption d;
    d.SetKeyWithIV( key, key.size(), iv);
    d.SpecifyDataLengths( 0, decodedText.size()-TAG_SIZE, 0 ); 

    // Decrypt the text using CTR mode
    string decryptedText;
    AuthenticatedDecryptionFilter df( d,
        new StringSink( decryptedText )
    ); // AuthenticatedDecryptionFilter

    StringSource ss2( decodedText, true,
        new Redirector( df )
    ); // StringSource

    return decryptedText; 
}   


/*****************************************************\
\*****************************************************/

//------------------Main----------------------//
//--------------------------------------------//
int main(int argc, char *argv[])
{

    
    #ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
    #endif
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    int inputChoice;
    cout << "Would you like to input from:\n"
          << "1. Terminal\n"
          << "2. From file\n"
          << "Please enter your choice (1-2): ";
    cin >> inputChoice;
    cin.ignore();
    switch (inputChoice){
        case 1: {
            cout << "This is read from terminal mode" << endl;
            int aescipher;
            cout << "Would you like to perform:\n"
                  << "1. Key and IV generation\n"
                  << "2. Encryption\n"
                  << "3. Decryption\n"
                  << "Please enter your choice (1-3): ";
            cin >> aescipher;
    
            switch (aescipher) {
                case 1: {
                    AutoSeededRandomPool prng;

                    SecByteBlock key(AES::MAX_KEYLENGTH);
                    prng.GenerateBlock(key, key.size());

                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));

                    // Convert key and IV to hexadecimal strings for storage or transmission
                    string encodedKey, encodedIV;
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encodedKey)));
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encodedIV)));

                    cout << "Generated Key: " << string(encodedKey) << endl;
                    cout << "Generated IV: " << string(encodedIV) << endl;

                    break;
                }
                case 2: {
                    int encryptionMode;
                    cout << "Select the encryption mode:\n"
                          << "1. ECB Mode\n"
                          << "2. CBC Mode\n"
                          << "3. CFB Mode\n"
                          << "4. OFB Mode\n"
                          << "5. CTR Mode\n"
                          << "6. XTS Mode\n"
                          << "7. GCM Mode\n"
                          << "8. CCM Mode\n"
                          << "Please enter the mode (1-8): ";
                    cin >> encryptionMode;

                    string inputText;
                    cout << "Enter the plaintext to encrypt: ";

                    cin.ignore(); // Consume the newline character
                    getline(cin, inputText);

                    string inputString = inputText;

                    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[AES::BLOCKSIZE];

                    cout << "Enter the Key (hexadecimal): ";
                    string keyHex;

                    cin >> keyHex;
                    cin.ignore();
                    string keyString = keyHex;

                    cout << "Enter the IV (hexadecimal): ";
                    string ivHex;

                    cin >> ivHex;
                    cin.ignore(); // Consume the newline character
                    string ivHex_str = ivHex;

                    string result_enc;

                    switch (encryptionMode) {
                        case 1:
                        {
                            // ECB Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = ecb_encrypt(plainText, keyString);
                            break;
                        }
                        case 2:
                        {
                            // CBC Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = cbc_encrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 3:
                        {
                            // CFB Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = cfb_encrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 4:
                        {
                            // OFB Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = ofb_encrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 5:
                        {
                            // CTR Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = ctr_encrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 6:
                        {
                            // XTS Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = xts_encrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 7:
                        {
                            // GCM Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = gcm_encrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 8:
                        {
                            // CCM Mode encryption logic
                            string plainText = string(inputString);
                            result_enc = ccm_encrypt(plainText, keyString, ivHex_str);
                            break;
                        }
                    
                        default:
                            cout << "Invalid encryption mode\n";
                    }

                    cout << "Encrypted text: " << string(result_enc) << endl;

                    break;
                }
            
                case 3: {
                    int decryptionMode;
                    cout << "Select the decryption mode:\n"
                          << "1. ECB Mode\n"
                          << "2. CBC Mode\n"
                          << "3. CFB Mode\n"
                          << "4. OFB Mode\n"
                          << "5. CTR Mode\n"
                          << "6. XTS Mode\n"
                          << "7. GCM Mode\n"
                          << "8. CCM Mode\n"
                          << "Please enter the mode (1-8): ";
                    cin >> decryptionMode;

                    string inputText;
                    cout << "Enter the cipher text to decrypt (base64): ";

                    cin.ignore(); // Consume the newline character
                    getline(cin, inputText);

                    string inputString = inputText;

                    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[AES::BLOCKSIZE];

                    cout << "Enter the Key (hexadecimal): ";
                    string keyHex;

                    cin >> keyHex;
                    cin.ignore();
                    string keyString = keyHex;

                    cout << "Enter the IV (hexadecimal): ";
                    string ivHex;

                    cin >> ivHex;
                    cin.ignore();
                    string ivHex_str = ivHex;


                    string result_dec;

                    switch(decryptionMode){
                        case 1:{
                            string plainText = string(inputString);
                            result_dec = ecb_decrypt(plainText, keyString);
                            break;
                        }

                        case 2:
                        {
                            // CBC Mode decryption logic
                            string plainText = string(inputString);
                            result_dec = cbc_decrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 3:
                        {
                            // CFB Mode decryption logic
                            string plainText = string(inputString);
                            result_dec = cfb_decrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 4:
                        {
                            // OFB Mode decryption logic
                            string plainText = string(inputString);
                            result_dec = ofb_decrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 5:
                        {
                            // OFB Mode decryption logic
                            string plainText = string(inputString);
                            result_dec = ctr_decrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 6:
                        {
                            // XTS Mode decryption logic
                            string plainText = string(inputString);
                            result_dec = xts_decrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 7:
                        {
                            // GCM Mode decryption logic
                            string plainText = string(inputString);
                            result_dec = gcm_decrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        case 8:
                        {
                            // CCM Mode decryption logic
                            string plainText = string(inputString);
                            result_dec = ccm_decrypt(plainText, keyString, ivHex_str);
                            break;
                        }

                        default:
                            cout << "Invalid decryption mode\n";
                    }
                    cout << "Decrypted text: " << string(result_dec) << endl;
                    break;
                }
                default:
                    cout << "Invalid input\n";
            }
            break;
        }
    
        case 2: {
            cout << "This is read from file mode:" << endl;
            int aescipher;
            cout << "Would you like to perform:\n"
                  << "1. Key and IV generation\n"
                  << "2. Encryption\n"
                  << "3. Decryption\n"
                  << "Please enter your choice (1-3): ";
            cin >> aescipher;
            cin.ignore();
            switch (aescipher)
            {
                case 1: {
                    AutoSeededRandomPool prng;

                    SecByteBlock key(AES::MAX_KEYLENGTH);
                    prng.GenerateBlock(key, key.size());

                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));

                    // Convert key and IV to hexadecimal strings for storage or transmission
                    string encodedKey, encodedIV;
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encodedKey)));
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encodedIV)));
                    

                    cout << "Generated Key: " << string(encodedKey) << endl;
                    cout << "Generated IV: " << string(encodedIV) << endl;

                    save_to_file_key_iv(encodedKey, encodedIV);

                    break;
                }
                case 2: {
                    int encryptionMode;
                    cout << "Select the encryption mode:\n"
                          << "1. ECB Mode\n"
                          << "2. CBC Mode\n"
                          << "3. CFB Mode\n"
                          << "4. OFB Mode\n"
                          << "5. CTR Mode\n"
                          << "6. XTS Mode\n"
                          << "7. GCM Mode\n"
                          << "8. CCM Mode\n"
                          << "Please enter the mode (1-8): ";
                    cin >> encryptionMode;
                    cin.ignore(); // Consume the newline character
    
                    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>); // UTF-8


                    string fileName;
                    cout << "Choose which file for encryption (1 -> 6): ";
                    cin >> fileName;


                    string result_enc;

                    string plaintextFileName = "ztext/plaintext" + fileName + ".txt";

                    // Read PLAINTEXT.TXT
                    string inputText;
                    std::ifstream text(plaintextFileName);
                    if (!text){
                        std::cout << "Can't read plaintext.txt\n";
                    } else {
                        text.imbue(loc);
                        std::getline(text, inputText);
                        text.close();
                    }
                    


                    string inputString = inputText;
                    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[AES::BLOCKSIZE];

                    // Read KEY and IV
                    string keyHex, ivHex;
                    std::ifstream keyiv("key_iv.txt");
                    if (!keyiv){
                        std::cout << "Can't read key_iv.txt\n";
                    } else {
                        keyiv.imbue(loc);
                        std::getline(keyiv, keyHex);
                        std::getline(keyiv, ivHex);
                        keyiv.close();
                    }


                    string keyString = keyHex;
                    string ivHex_str = ivHex;

                    auto start = std::chrono::high_resolution_clock::now();
                    for(int i = 0; i < 10000; i++){
                        switch (encryptionMode){
                            case 1:{
                                // ECB Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = ecb_encrypt(plainText, keyString);
                                break;
                            }
                            case 2:{
                                // CBC Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = cbc_encrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 3:{
                                // CFB Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = cfb_encrypt(plainText, keyString, ivHex_str);
                                break;
                            }
                            case 4:{
                                // OFB Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = ofb_encrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 5:{
                                // CTR Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = ctr_encrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 6:{
                                // XTS Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = xts_encrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 7:{
                                // GCM Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = gcm_encrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 8:{
                                // CCM Mode encryption logic
                                string plainText = string(inputString);
                                result_enc = ccm_encrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            default:
                                cout << "Invalid encryption mode" << endl;
                        }
                    }
                    auto end = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                    double averageTime = static_cast<double>(duration) / 10000.0;
                    std::cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                    
                    save_to_file_enc(result_enc);
                    break;
                    
                }
                case 3: {
                    int decryptionMode;
                    cout << "Select the decryption mode:\n"
                          << "1. ECB Mode\n"
                          << "2. CBC Mode\n"
                          << "3. CFB Mode\n"
                          << "4. OFB Mode\n"
                          << "5. CTR Mode\n"
                          << "6. XTS Mode\n"
                          << "7. GCM Mode\n"
                          << "8. CCM Mode\n"
                          << "Please enter the mode (1-8): ";
                    cin >> decryptionMode;
                    cin.ignore(); // Consume the newline character
    
                    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>); // UTF-8
                    string inputText;

                    auto start = std::chrono::high_resolution_clock::now();
                    string result_dec;


                    std::ifstream enc("encrypted.txt", std::ios::in);
                    if (!enc){
                        std::cout << "Can't read encrypted.txt\n";
                    } else {
                        enc.imbue(loc);
                        std::getline(enc, inputText);
                        enc.close();
                    }


                    string inputString = inputText;
                    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    string keyHex, ivHex;
                    std::ifstream keyiv("key_iv.txt");
                    if (!keyiv) {
                        std::cout << "Can't read key_iv.txt\n";
                    } else {
                        keyiv.imbue(loc);
                        std::getline(keyiv, keyHex);
                        std::getline(keyiv, ivHex);
                        keyiv.close();
                    }


                    string keyString = keyHex;
                    string ivHex_str = ivHex;


                    for(int i = 0; i < 10000; i++){
                        switch (decryptionMode)
                        {
                            case 1:
                            {
                                // ECB Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = ecb_decrypt(plainText, keyString);
                                break;
                            }

                            case 2:
                            {
                                // CBC Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = cbc_decrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 3:
                            {
                                // CFB Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = cfb_decrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 4:
                            {
                                // OFB Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = ofb_decrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 5:
                            {
                                // CTR Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = ctr_decrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 6:
                            {
                                // XTS Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = xts_decrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 7:
                            {
                                // GCM Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = gcm_decrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            case 8:
                            {
                                // CCM Mode decryption logic
                                string plainText = string(inputString);
                                result_dec = ccm_decrypt(plainText, keyString, ivHex_str);
                                break;
                            }

                            default:
                                cout << "Invalid decryption mode\n";
                        }
                    }
                    auto end = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                    double averageTime = static_cast<double>(duration) / 10000.0;
                    std::cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                    save_to_file_dec(result_dec);
                    
                    break;
                }       
                default:
                    cout << "Invalid input\n";
            }
        }
        return 0;
    }
    return 0;
}
// Method to convert string to wstrign and
wstring string_to_wstring(const string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

string wstring_to_string(const wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
