#include "Cryptography/SHA256.h"
#include "Cryptography/HMAC_SHA256.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/AES128.h"

#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>

/**
 * @brief Example entrypoint
 */
int main()
{
    std::cout << "Hello, this is TLS server !" << std::endl;

    std::cout << "\n\nTesting SHA256 implementation..." << std::endl;
    std::string input = "abc";
    std::string output = Xale::Cryptography::SHA256::hashToString(input);

    std::cout << output << std::endl;

    std::cout << "\n\nTesting HMAC-SHA256 implementation..." << std::endl;
    input = "abc";
    std::string key = "xale";
    std::string hmacOutput = Xale::Cryptography::HMAC_SHA256::macToString(key, input);

    std::cout << hmacOutput << std::endl;

    std::cout << "\n\nTesting HKDF implementation..." << std::endl;
    std::vector<std::uint8_t> rfcMessage(22, 0x0b);
    std::vector<std::uint8_t> rfcSalt = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    std::vector<std::uint8_t> rfcInfo = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};

    auto toHex = [](const std::uint8_t* data, std::size_t len) {
        std::ostringstream oss;
        for (std::size_t i = 0; i < len; ++i)
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
        return oss.str();
    };

    std::cout << "Message: " << toHex(rfcMessage.data(), rfcMessage.size()) << std::endl;
    std::cout << "Salt:    " << toHex(rfcSalt.data(), rfcSalt.size()) << std::endl;
    std::cout << "Info:    " << toHex(rfcInfo.data(), rfcInfo.size()) << std::endl;

    auto rfcPrk = Xale::Cryptography::HKDF::extract(rfcSalt, rfcMessage);
    auto rfcOkm = Xale::Cryptography::HKDF::expand(rfcPrk.data(), rfcPrk.size(), rfcInfo.data(), rfcInfo.size(), 42);

    std::cout << "PRK: " << toHex(rfcPrk.data(), rfcPrk.size()) << std::endl;
    std::cout << "OKM: " << toHex(rfcOkm.data(), rfcOkm.size()) << std::endl;

    std::cout << "\n\nTesting AES128 implementation..." << std::endl;
    std::vector<std::uint8_t> aesKey = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    std::vector<std::uint8_t> aesPlaintext = {
        0x6b,0xc1,0xbe,0xe2,0xe3,0x2b,0x7e,0x15,
        0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88
    };

    std::cout << "Key:       " << toHex(aesKey.data(), aesKey.size()) << std::endl;
    std::cout << "Plaintext: " << toHex(aesPlaintext.data(), aesPlaintext.size()) << std::endl;

    auto aesCiphertext = Xale::Cryptography::AES128::encrypt(aesKey.data(), aesPlaintext.data());
    std::cout << "Ciphertext: " << toHex(aesCiphertext.data(), aesCiphertext.size()) << std::endl;
    auto aesDecrypted = Xale::Cryptography::AES128::decrypt(aesKey.data(), aesCiphertext.data());
    std::cout << "Decrypted:  " << toHex(aesDecrypted.data(), aesDecrypted.size()) << std::endl;

    return 0;
}
