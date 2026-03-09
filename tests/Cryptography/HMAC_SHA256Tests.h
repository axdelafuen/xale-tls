#ifndef HMAC_SHA256_TEST_H
#define HMAC_SHA256_TEST_H

#include "Cryptography/HMAC_SHA256.h"
#include <string>
#include <vector>
#include <cstdint>

#define DECLARE_HMAC_SHA256_TEST(name) DECLARE_TEST(CRYPTO, hmac_sha256_##name)

namespace Xale::Tests
{
    // Test Case PRF-1: Short key (20 bytes), "Hi There"
    DECLARE_HMAC_SHA256_TEST(rfc4868_prf1)
    {
        auto key  = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        auto data = hexToBytes("4869205468657265"); // "Hi There"
        std::string expect = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case PRF-2: Key = "Jefe", Data = "what do ya want for nothing?"
    DECLARE_HMAC_SHA256_TEST(rfc4868_prf2)
    {
        auto key  = hexToBytes("4a656665"); // "Jefe"
        auto data = hexToBytes("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
        std::string expect = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case PRF-3: Key = 20 bytes of 0xaa, Data = 50 bytes of 0xdd
    DECLARE_HMAC_SHA256_TEST(rfc4868_prf3)
    {
        auto key  = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        auto data = hexToBytes(
            "dddddddddddddddddddddddddddddddd"
            "dddddddddddddddddddddddddddddddd"
            "dddddddddddddddddddddddddddddddd"
            "dddd");
        std::string expect = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case PRF-4: Key = 25 bytes, Data = 50 bytes of 0xcd
    DECLARE_HMAC_SHA256_TEST(rfc4868_prf4)
    {
        auto key  = hexToBytes("0102030405060708090a0b0c0d0e0f10111213141516171819");
        auto data = hexToBytes(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            "cdcd");
        std::string expect = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case PRF-5: Key = 131 bytes of 0xaa, Data = "Test Using Larger..."
    DECLARE_HMAC_SHA256_TEST(rfc4868_prf5)
    {
        auto key = hexToBytes(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaa");
        auto data = hexToBytes(
            "54657374205573696e67204c61726765"
            "72205468616e20426c6f636b2d53697a"
            "65204b6579202d2048617368204b6579"
            "204669727374");
        std::string expect = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case PRF-6: Key = 131 bytes of 0xaa, larger data
    DECLARE_HMAC_SHA256_TEST(rfc4868_prf6)
    {
        auto key = hexToBytes(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaa");
        auto data = hexToBytes(
            "54686973206973206120746573742075"
            "73696e672061206c6172676572207468"
            "616e20626c6f636b2d73697a65206b65"
            "7920616e642061206c61726765722074"
            "68616e20626c6f636b2d73697a652064"
            "6174612e20546865206b6579206e6565"
            "647320746f2062652068617368656420"
            "6265666f7265206265696e6720757365"
            "642062792074686520484d414320616c"
            "676f726974686d2e");
        std::string expect = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case AUTH256-1: Key = 32 bytes of 0x0b, "Hi There"
    DECLARE_HMAC_SHA256_TEST(rfc4868_auth256_1)
    {
        auto key  = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        auto data = hexToBytes("4869205468657265"); // "Hi There"
        std::string expect = "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case AUTH256-2: Key = "JefeJefeJefeJefeJefeJefeJefeJefe" (32 bytes)
    DECLARE_HMAC_SHA256_TEST(rfc4868_auth256_2)
    {
        auto key  = hexToBytes("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665");
        auto data = hexToBytes("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
        std::string expect = "167f928588c5cc2eef8e3093caa0e87c9ff566a14794aa61648d81621a2a40c6";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case AUTH256-3: Key = 32 bytes of 0xaa, Data = 50 bytes of 0xdd
    DECLARE_HMAC_SHA256_TEST(rfc4868_auth256_3)
    {
        auto key  = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        auto data = hexToBytes(
            "dddddddddddddddddddddddddddddddd"
            "dddddddddddddddddddddddddddddddd"
            "dddddddddddddddddddddddddddddddd"
            "dddd");
        std::string expect = "cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }

    // Test Case AUTH256-4: Key = 32 bytes (0x01..0x20), Data = 50 bytes of 0xcd
    DECLARE_HMAC_SHA256_TEST(rfc4868_auth256_4)
    {
        auto key  = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        auto data = hexToBytes(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            "cdcd");
        std::string expect = "372efcf9b40b35c2115b1346903d2ef42fced46f0846e7257bb156d3d7b30d3f";

        auto mac = Xale::Cryptography::HMAC_SHA256::mac(key.data(), key.size(), data.data(), data.size());
        return bytesToHex(mac.data(), mac.size()) == expect;
    }
}

#endif // HMAC_SHA256_TEST_H
