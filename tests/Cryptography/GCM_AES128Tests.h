#ifndef GCM_AES128_TEST_H
#define GCM_AES128_TEST_H

#include "Cryptography/GCM_AES128.h"

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <algorithm>

#define DECLARE_GCM_AES128_TEST(name) DECLARE_TEST(CRYPTO, gcm_aes128_##name)

namespace Xale::Tests
{
    // Helper: convert hex string to std::array<uint8_t, 16>
    static std::array<std::uint8_t, 16> hexToArray16(const std::string& hex)
    {
        auto vec = hexToBytes(hex);
        std::array<std::uint8_t, 16> arr = {};
        std::copy_n(vec.begin(),
                    std::min(vec.size(), static_cast<std::size_t>(16)),
                    arr.begin());
        return arr;
    }

    // all-zero key, 96-bit IV, empty AAD, empty plaintext
    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc1_encrypt)
    {
        auto key = hexToArray16("00000000000000000000000000000000");
        auto iv  = hexToBytes("000000000000000000000000");
        std::vector<std::uint8_t> aad;
        std::vector<std::uint8_t> pt;

        auto [ct, tag] = Xale::Cryptography::GCM_AES128::encrypt(key, iv, aad, pt);

        return ct.empty()
            && bytesToHex(tag.data(), tag.size()) == "58e2fccefa7e3061367f1d57a4e7455a";
    }

    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc1_decrypt)
    {
        auto key = hexToArray16("00000000000000000000000000000000");
        auto iv  = hexToBytes("000000000000000000000000");
        std::vector<std::uint8_t> aad;
        std::vector<std::uint8_t> ct;
        auto tag = hexToArray16("58e2fccefa7e3061367f1d57a4e7455a");

        auto result = Xale::Cryptography::GCM_AES128::decrypt(key, iv, aad, ct, tag);
        return result.has_value() && result->empty();
    }

    //all-zero key, 16-byte zero plaintext, empty AAD
    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc2_encrypt)
    {
        auto key = hexToArray16("00000000000000000000000000000000");
        auto iv  = hexToBytes("000000000000000000000000");
        std::vector<std::uint8_t> aad;
        auto pt  = hexToBytes("00000000000000000000000000000000");

        auto [ct, tag] = Xale::Cryptography::GCM_AES128::encrypt(key, iv, aad, pt);

        return bytesToHex(ct.data(), ct.size())   == "0388dace60b6a392f328c2b971b2fe78"
            && bytesToHex(tag.data(), tag.size()) == "ab6e47d42cec13bdf53a67b21257bddf";
    }

    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc2_decrypt)
    {
        auto key = hexToArray16("00000000000000000000000000000000");
        auto iv  = hexToBytes("000000000000000000000000");
        std::vector<std::uint8_t> aad;
        auto ct  = hexToBytes("0388dace60b6a392f328c2b971b2fe78");
        auto tag = hexToArray16("ab6e47d42cec13bdf53a67b21257bddf");

        auto result = Xale::Cryptography::GCM_AES128::decrypt(key, iv, aad, ct, tag);
        return result.has_value()
            && bytesToHex(result->data(), result->size()) == "00000000000000000000000000000000";
    }

    // 64-byte plaintext, no AAD
    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc3_encrypt)
    {
        auto key = hexToArray16("feffe9928665731c6d6a8f9467308308");
        auto iv  = hexToBytes("cafebabefacedbaddecaf888");
        std::vector<std::uint8_t> aad;
        auto pt  = hexToBytes(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255");

        std::string expectCt =
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985";
        std::string expectTag = "4d5c2af327cd64a62cf35abd2ba6fab4";

        auto [ct, tag] = Xale::Cryptography::GCM_AES128::encrypt(key, iv, aad, pt);

        return bytesToHex(ct.data(), ct.size())   == expectCt
            && bytesToHex(tag.data(), tag.size()) == expectTag;
    }

    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc3_decrypt)
    {
        auto key = hexToArray16("feffe9928665731c6d6a8f9467308308");
        auto iv  = hexToBytes("cafebabefacedbaddecaf888");
        std::vector<std::uint8_t> aad;
        auto ct  = hexToBytes(
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985");
        auto tag = hexToArray16("4d5c2af327cd64a62cf35abd2ba6fab4");

        std::string expectPt =
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255";

        auto result = Xale::Cryptography::GCM_AES128::decrypt(key, iv, aad, ct, tag);
        return result.has_value()
            && bytesToHex(result->data(), result->size()) == expectPt;
    }

    // 60-byte plaintext with 20-byte AAD
    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc4_encrypt)
    {
        auto key = hexToArray16("feffe9928665731c6d6a8f9467308308");
        auto iv  = hexToBytes("cafebabefacedbaddecaf888");
        auto aad = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        auto pt  = hexToBytes(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39");

        std::string expectCt =
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091";
        std::string expectTag = "5bc94fbc3221a5db94fae95ae7121a47";

        auto [ct, tag] = Xale::Cryptography::GCM_AES128::encrypt(key, iv, aad, pt);

        return bytesToHex(ct.data(), ct.size())   == expectCt
            && bytesToHex(tag.data(), tag.size()) == expectTag;
    }

    DECLARE_GCM_AES128_TEST(mcgrew_viega_tc4_decrypt)
    {
        auto key = hexToArray16("feffe9928665731c6d6a8f9467308308");
        auto iv  = hexToBytes("cafebabefacedbaddecaf888");
        auto aad = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        auto ct  = hexToBytes(
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091");
        auto tag = hexToArray16("5bc94fbc3221a5db94fae95ae7121a47");

        std::string expectPt =
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39";

        auto result = Xale::Cryptography::GCM_AES128::decrypt(key, iv, aad, ct, tag);
        return result.has_value()
            && bytesToHex(result->data(), result->size()) == expectPt;
    }

    // Roundtrip: encrypt then decrypt must return the original plaintext
    DECLARE_GCM_AES128_TEST(roundtrip)
    {
        auto key = hexToArray16("feffe9928665731c6d6a8f9467308308");
        auto iv  = hexToBytes("cafebabefacedbaddecaf888");
        auto aad = hexToBytes("feedfacedeadbeef");
        auto pt  = hexToBytes(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72");

        auto [ct, tag] = Xale::Cryptography::GCM_AES128::encrypt(key, iv, aad, pt);
        auto result    = Xale::Cryptography::GCM_AES128::decrypt(key, iv, aad, ct, tag);

        return result.has_value()
            && bytesToHex(result->data(), result->size()) == bytesToHex(pt.data(), pt.size());
    }

    // Authentication: tampered ciphertext must be rejected
    DECLARE_GCM_AES128_TEST(tampered_ciphertext_rejected)
    {
        auto key = hexToArray16("feffe9928665731c6d6a8f9467308308");
        auto iv  = hexToBytes("cafebabefacedbaddecaf888");
        auto aad = hexToBytes("feedfacedeadbeef");
        auto pt  = hexToBytes("d9313225f88406e5a55909c5aff5269a");

        auto [ct, tag] = Xale::Cryptography::GCM_AES128::encrypt(key, iv, aad, pt);

        // Flip one bit in the ciphertext
        ct[0] ^= 0x01;

        auto result = Xale::Cryptography::GCM_AES128::decrypt(key, iv, aad, ct, tag);
        return !result.has_value();
    }

    // Authentication: tampered tag must be rejected
    DECLARE_GCM_AES128_TEST(tampered_tag_rejected)
    {
        auto key = hexToArray16("feffe9928665731c6d6a8f9467308308");
        auto iv  = hexToBytes("cafebabefacedbaddecaf888");
        std::vector<std::uint8_t> aad;
        auto pt  = hexToBytes("00000000000000000000000000000000");

        auto [ct, tag] = Xale::Cryptography::GCM_AES128::encrypt(key, iv, aad, pt);

        // Flip one bit in the tag
        tag[0] ^= 0x01;

        auto result = Xale::Cryptography::GCM_AES128::decrypt(key, iv, aad, ct, tag);
        return !result.has_value();
    }
}

#endif // GCM_AES128_TEST_H
