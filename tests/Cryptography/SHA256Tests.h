#ifndef SHA256_TEST_H
#define SHA256_TEST_H

#include "Cryptography/SHA256.h"
#include <string>

#define DECLARE_SHA256_TEST(name) DECLARE_TEST(CRYPTO, sha256##name)

namespace Xale::Tests
{
    DECLARE_SHA256_TEST(hash_success_short)
    {
        std::string expect = "87967e63a4606a8c504ee0cf3609969bc525ea12b02b5894f88d56670a7a5d7e";
        std::string input = "xale123";
        std::string output = Xale::Cryptography::SHA256::hashToString(input);

        return expect == output;
    }

    DECLARE_SHA256_TEST(hash_success_long)
    {
        std::string expect = "f753afcb89e4c6518dc07bf25b71de6220ccd1bc59746aab96c8e30a7d5a909e";
        std::string input = "xale1230987654XALE**__{xale}__--;;;;;;;xale";
        std::string output = Xale::Cryptography::SHA256::hashToString(input);

        return expect == output;
    }

    DECLARE_SHA256_TEST(hash_fail)
    {
        std::string expect = "87967e63a4606a8c504ee0cf3609969bc525ea12b02b5894f88d56670a7a5d7e";
        std::string input = "xale1234*";
        std::string output = Xale::Cryptography::SHA256::hashToString(input);

        return expect != output;
    }
}

#endif // SHA256_TEST_H
