#ifndef HMAC_SHA256_TEST_H
#define HMAC_SHA256_TEST_H

#include "Cryptography/HMAC_SHA256.h"
#include <string>

#define DECLARE_HMAC_SHA256_TEST(name) DECLARE_TEST(CRYPTO, hmac_sha256_##name)

namespace Xale::Tests
{
    DECLARE_HMAC_SHA256_TEST(hash_success_short)
    {
        std::string expect = "f868f5ca4cab401ae93a51716df017d3701cbfe6377aec6b9d0251db18b738dd";
        std::string input = "xale123";
        std::string key = "xale";
        
        std::string output = Xale::Cryptography::HMAC_SHA256::macToString(key, input);
        
        return expect == output;
    }

    DECLARE_HMAC_SHA256_TEST(hash_success_long)
    {
        std::string expect = "55e415c33d27fbddcfa92b0380414577351e2ede98d2be23dd84cb3f4503e8de";
        std::string input = "xale1230987654XALE**__{xale}__--;;;;;;;xale";
        std::string key = "xale";
        
        std::string output = Xale::Cryptography::HMAC_SHA256::macToString(key, input);

        return expect == output;
    }

    DECLARE_HMAC_SHA256_TEST(hash_fail)
    {
        std::string expect = "f868f5ca4cab401ae93a51716df017d3701cbfe6377aec6b9d0251db18b738dd";
        std::string input = "xale1234*";
        std::string key = "xale";
        
        std::string output = Xale::Cryptography::HMAC_SHA256::macToString(key, input);
        
        return expect != output;
    }
}

#endif // HMAC_SHA256_TEST_H
