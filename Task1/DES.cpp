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
#include "cryptopp/aes.h"
using CryptoPP::AES;
#include "cryptopp/DES.h"
using CryptoPP::DES;

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
    std::ofstream fout("key_iv_2.txt");
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
    std::ofstream out("encrypted2.txt");
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
    std::ofstream out("decrypted2.txt");
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    CBC_Mode<DES>::Encryption e;
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
            ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CBC Mode decryption logic
    CBC_Mode<DES>::Decryption d;
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
    ECB_Mode<DES>::Encryption e;
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
    ECB_Mode<DES>::Decryption d;
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CFB Mode decryption logic
    CFB_Mode<DES>::Decryption d;
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource

    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CFB Mode encryption logic
    CFB_Mode<DES>::Encryption e;
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // OFB Mode encryption logic
    OFB_Mode<DES>::Encryption e;
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // OFB Mode decryption logic
    OFB_Mode<DES>::Decryption d;
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CTR Mode encryption logic
    CTR_Mode<DES>::Encryption e;
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
    CryptoPP::byte iv[DES::BLOCKSIZE];
    StringSource(ivHex, true,
        new HexDecoder(
            new StringSink(iv_string)
        ) // HexDecoder
    ); // StringSource
    memcpy(iv, iv_string.c_str(), sizeof(iv));

    // CTR Mode decryption logic
    CTR_Mode<DES>::Decryption d;
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
            int DEScipher;
            cout << "Would you like to perform:\n"
                  << "1. Key and IV generation\n"
                  << "2. Encryption\n"
                  << "3. Decryption\n"
                  << "Please enter your choice (1-3): ";
            cin >> DEScipher;
    
            switch (DEScipher) {
                case 1: {
                    AutoSeededRandomPool prng;

                    SecByteBlock key(DES::MAX_KEYLENGTH);
                    prng.GenerateBlock(key, key.size());

                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));

                    // Convert key and IV to hexadecimal strings for storage or transmission
                    string encodedKey, encodedIV;
                    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encodedKey)));
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
                          << "Please enter the mode (1-5): ";
                    cin >> encryptionMode;

                    string inputText;
                    cout << "Enter the plaintext to encrypt: ";

                    cin.ignore(); // Consume the newline character
                    getline(cin, inputText);

                    string inputString = inputText;

                    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[DES::BLOCKSIZE];

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
                          << "Please enter the mode (1-5): ";
                    cin >> decryptionMode;

                    string inputText;
                    cout << "Enter the cipher text to decrypt (base64): ";

                    cin.ignore(); // Consume the newline character
                    getline(cin, inputText);

                    string inputString = inputText;

                    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[DES::BLOCKSIZE];

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
            int DEScipher;
            cout << "Would you like to perform:\n"
                  << "1. Key and IV generation\n"
                  << "2. Encryption\n"
                  << "3. Decryption\n"
                  << "Please enter your choice (1-3): ";
            cin >> DEScipher;
            cin.ignore();
            switch (DEScipher)
            {
                case 1: {
                    AutoSeededRandomPool prng;

                    SecByteBlock key(DES::MAX_KEYLENGTH);
                    prng.GenerateBlock(key, key.size());

                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));

                    // Convert key and IV to hexadecimal strings for storage or transmission
                    string encodedKey, encodedIV;
                    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encodedKey)));
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
                          << "Please enter the mode (1-5): ";
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
                    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[DES::BLOCKSIZE];

                    // Read KEY and IV
                    string keyHex, ivHex;
                    std::ifstream keyiv("key_iv_2.txt");
                    if (!keyiv){
                        std::cout << "Can't read key_iv_2.txt\n";
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
                          << "Please enter the mode (1-5): ";
                    cin >> decryptionMode;
                    cin.ignore(); // Consume the newline character
    
                    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>); // UTF-8
                    string inputText;

                    auto start = std::chrono::high_resolution_clock::now();
                    string result_dec;


                    std::ifstream enc("encrypted2.txt", std::ios::in);
                    if (!enc){
                        std::cout << "Can't read encrypted.txt\n";
                    } else {
                        enc.imbue(loc);
                        std::getline(enc, inputText);
                        enc.close();
                    }


                    string inputString = inputText;
                    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    string keyHex, ivHex;
                    std::ifstream keyiv("key_iv_2.txt");
                    if (!keyiv) {
                        std::cout << "Can't read key_iv_2.txt\n";
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
