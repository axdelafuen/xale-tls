#ifndef AES128_TEST_H
#define AES128_TEST_H

#include "Cryptography/AES128.h"
#include <string>
#include <vector>
#include <cstdint>

#define DECLARE_AES128_TEST(name) DECLARE_TEST(CRYPTO, aes128_##name)

namespace Xale::Tests
{
    // NIST FIPS 197 Appendix B - AES-128 Encrypt
    DECLARE_AES128_TEST(fips197_appb_encrypt)
    {
        auto key  = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto pt   = hexToBytes("3243f6a8885a308d313198a2e0370734");
        std::string expect = "3925841d02dc09fbdc118597196a0b32";

        auto ct = Xale::Cryptography::AES128::encrypt(key.data(), pt.data());
        return bytesToHex(ct.data(), ct.size()) == expect;
    }

    DECLARE_AES128_TEST(fips197_appb_decrypt)
    {
        auto key  = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto ct   = hexToBytes("3925841d02dc09fbdc118597196a0b32");
        std::string expect = "3243f6a8885a308d313198a2e0370734";

        auto pt = Xale::Cryptography::AES128::decrypt(key.data(), ct.data());
        return bytesToHex(pt.data(), pt.size()) == expect;
    }

    // NIST FIPS 197 Appendix C.1 - AES-128
    DECLARE_AES128_TEST(fips197_appc1_encrypt)
    {
        auto key  = hexToBytes("000102030405060708090a0b0c0d0e0f");
        auto pt   = hexToBytes("00112233445566778899aabbccddeeff");
        std::string expect = "69c4e0d86a7b0430d8cdb78070b4c55a";

        auto ct = Xale::Cryptography::AES128::encrypt(key.data(), pt.data());
        return bytesToHex(ct.data(), ct.size()) == expect;
    }

    DECLARE_AES128_TEST(fips197_appc1_decrypt)
    {
        auto key  = hexToBytes("000102030405060708090a0b0c0d0e0f");
        auto ct   = hexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a");
        std::string expect = "00112233445566778899aabbccddeeff";

        auto pt = Xale::Cryptography::AES128::decrypt(key.data(), ct.data());
        return bytesToHex(pt.data(), pt.size()) == expect;
    }

    // Roundtrip: encrypt then decrypt must return the original plaintext
    DECLARE_AES128_TEST(roundtrip)
    {
        auto key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto pt  = hexToBytes("6bc1bee22e409f96e93d7e117393172a");

        auto ct  = Xale::Cryptography::AES128::encrypt(key.data(), pt.data());
        auto out = Xale::Cryptography::AES128::decrypt(key.data(), ct.data());

        return bytesToHex(out.data(), out.size()) == bytesToHex(pt.data(), pt.size());
    }

    // Zero key / zero block
    DECLARE_AES128_TEST(zero_key_zero_block_encrypt)
    {
        auto key = hexToBytes("00000000000000000000000000000000");
        auto pt  = hexToBytes("00000000000000000000000000000000");
        std::string expect = "66e94bd4ef8a2c3b884cfa59ca342b2e";

        auto ct = Xale::Cryptography::AES128::encrypt(key.data(), pt.data());
        return bytesToHex(ct.data(), ct.size()) == expect;
    }

    DECLARE_AES128_TEST(zero_key_zero_block_decrypt)
    {
        auto key = hexToBytes("00000000000000000000000000000000");
        auto ct  = hexToBytes("66e94bd4ef8a2c3b884cfa59ca342b2e");
        std::string expect = "00000000000000000000000000000000";

        auto pt = Xale::Cryptography::AES128::decrypt(key.data(), ct.data());
        return bytesToHex(pt.data(), pt.size()) == expect;
    }

    // std::array overload
    DECLARE_AES128_TEST(array_overload_roundtrip)
    {
        std::array<std::uint8_t, 16> key = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        std::array<std::uint8_t, 16> pt = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
        };

        auto ct  = Xale::Cryptography::AES128::encrypt(key, pt);
        auto out = Xale::Cryptography::AES128::decrypt(key, ct);

        return out == pt;
    }
}

#endif // AES128_TEST_H
