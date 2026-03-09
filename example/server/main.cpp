#include "Cryptography/SHA256.h"
#include "Cryptography/HMAC_SHA256.h"

#include <string>
#include <iostream>

/**
 * @brief Example entrypoint
 */
int main()
{
    std::cout << "Hello, this is TLS server !" << std::endl;

    std::cout << "Testing SHA256 implementation..." << std::endl;
    std::string input = "abc";
    std::string output = Xale::Cryptography::SHA256::hashToString(input);

    std::cout << output << std::endl;

    std::cout << "Testing HMAC-SHA256 implementation..." << std::endl;
    input = "abc";
    std::string key = "xale";
    std::string hmacOutput = Xale::Cryptography::HMAC_SHA256::macToString(key, input);

    std::cout << hmacOutput << std::endl;
}
