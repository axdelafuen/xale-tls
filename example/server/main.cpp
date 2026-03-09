#include "Cryptography/SHA256.h"

#include <string>
#include <iostream>

/**
 * @brief Example entrypoint
 */
int main()
{
    std::cout << "Hello, this is TLS server !" << std::endl;

    std::string input = "abc";
    std::string output = Xale::Cryptography::SHA256::hashToString(input);

    std::cout << output << std::endl;
}
