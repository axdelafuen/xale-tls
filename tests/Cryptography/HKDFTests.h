#ifndef HKDF_TEST_H
#define HKDF_TEST_H

#include "Cryptography/HKDF.h"
#include "Cryptography/HMAC_SHA256.h"
#include <string>
#include <vector>
#include <cstdint>

#define DECLARE_HKDF_TEST(name) DECLARE_TEST(CRYPTO, hkdf_##name)

namespace Xale::Tests
{
    // RFC 5869 A.1 - Extract
    DECLARE_HKDF_TEST(rfc5869_a1_extract)
    {
        std::string expect = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        auto salt = hexToBytes("000102030405060708090a0b0c");
        auto ikm  = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

        auto prk = Xale::Cryptography::HKDF::extract(salt, ikm);

        return bytesToHex(prk.data(), prk.size()) == expect;
    }

    // RFC 5869 A.1 - Expand
    DECLARE_HKDF_TEST(rfc5869_a1_expand)
    {
        std::string expect = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        auto prk  = hexToBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        auto info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");

        auto okm = Xale::Cryptography::HKDF::expand(prk, info, 42);

        return bytesToHex(okm.data(), okm.size()) == expect;
    }

    // RFC 5869 A.2 - Extract (longer inputs)
    DECLARE_HKDF_TEST(rfc5869_a2_extract)
    {
        std::string expect = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
        auto salt = hexToBytes(
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        auto ikm = hexToBytes(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f");

        auto prk = Xale::Cryptography::HKDF::extract(salt, ikm);

        return bytesToHex(prk.data(), prk.size()) == expect;
    }

    // RFC 5869 A.2 - Expand (longer outputs)
    DECLARE_HKDF_TEST(rfc5869_a2_expand)
    {
        std::string expect =
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87";
        auto prk  = hexToBytes("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        auto info = hexToBytes(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        auto okm = Xale::Cryptography::HKDF::expand(prk, info, 82);

        return bytesToHex(okm.data(), okm.size()) == expect;
    }

    // RFC 5869 A.3 - Extract (zero-length salt)
    DECLARE_HKDF_TEST(rfc5869_a3_extract)
    {
        std::string expect = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
        std::vector<std::uint8_t> salt;
        auto ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

        auto prk = Xale::Cryptography::HKDF::extract(salt, ikm);

        return bytesToHex(prk.data(), prk.size()) == expect;
    }

    // RFC 5869 A.3 - Expand (zero-length info)
    DECLARE_HKDF_TEST(rfc5869_a3_expand)
    {
        std::string expect = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
        auto prk = hexToBytes("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        std::vector<std::uint8_t> info;

        auto okm = Xale::Cryptography::HKDF::expand(prk, info, 42);

        return bytesToHex(okm.data(), okm.size()) == expect;
    }

    // RFC 5869 A.1 - Wrong expected value
    DECLARE_HKDF_TEST(rfc5869_a1_extract_fail)
    {
        std::string expect = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        auto salt = hexToBytes("000102030405060708090a0b0c");
        auto ikm  = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0bFFFFFFFFFFFF");

        auto prk = Xale::Cryptography::HKDF::extract(salt, ikm);

        return bytesToHex(prk.data(), prk.size()) != expect;
    }
}

#endif // HKDF_TEST_H
