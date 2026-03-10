#ifndef SHA512_TEST_H
#define SHA512_TEST_H

#include "Cryptography/SHA512.h"
#include <string>

#define DECLARE_SHA512_TEST(name) DECLARE_TEST(CRYPTO, sha512_##name)

namespace Xale::Tests
{
    // NIST FIPS 180-4 / NIST CSRC Examples
    // SHA-512("abc")
    DECLARE_SHA512_TEST(nist_abc)
    {
        std::string expect =
            "ddaf35a193617aba"
            "cc417349ae204131"
            "12e6fa4e89a97ea2"
            "0a9eeee64b55d39a"
            "2192992a274fc1a8"
            "36ba3c23a3feebbd"
            "454d4423643ce80e"
            "2a9ac94fa54ca49f";
        std::string output = Xale::Cryptography::SHA512::hashToString("abc");
        return expect == output;
    }

    // SHA-512("") – empty string
    DECLARE_SHA512_TEST(nist_empty)
    {
        std::string expect =
            "cf83e1357eefb8bd"
            "f1542850d66d8007"
            "d620e4050b5715dc"
            "83f4a921d36ce9ce"
            "47d0d13c5d85f2b0"
            "ff8318d2877eec2f"
            "63b931bd47417a81"
            "a538327af927da3e";
        std::string output = Xale::Cryptography::SHA512::hashToString("");
        return expect == output;
    }

    // SHA-512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    DECLARE_SHA512_TEST(nist_448bit)
    {
        std::string expect =
            "204a8fc6dda82f0a"
            "0ced7beb8e08a416"
            "57c16ef468b228a8"
            "279be331a703c335"
            "96fd15c13b1b07f9"
            "aa1d3bea57789ca0"
            "31ad85c7a71dd703"
            "54ec631238ca3445";
        std::string output = Xale::Cryptography::SHA512::hashToString(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        return expect == output;
    }

    // SHA-512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
    //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    DECLARE_SHA512_TEST(nist_896bit)
    {
        std::string expect =
            "8e959b75dae313da"
            "8cf4f72814fc143f"
            "8f7779c6eb9f7fa1"
            "7299aeadb6889018"
            "501d289e4900f7e4"
            "331b99dec4b5433a"
            "c7d329eeb6dd2654"
            "5e96e55b874be909";
        std::string output = Xale::Cryptography::SHA512::hashToString(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        return expect == output;
    }

    // Roundtrip: same input produces same hash
    DECLARE_SHA512_TEST(deterministic)
    {
        std::string input = "The quick brown fox jumps over the lazy dog";
        std::string hash1 = Xale::Cryptography::SHA512::hashToString(input);
        std::string hash2 = Xale::Cryptography::SHA512::hashToString(input);
        return hash1 == hash2;
    }

    // Known vector: "The quick brown fox jumps over the lazy dog"
    DECLARE_SHA512_TEST(quick_brown_fox)
    {
        std::string expect =
            "07e547d9586f6a73"
            "f73fbac0435ed769"
            "51218fb7d0c8d788"
            "a309d785436bbb64"
            "2e93a252a954f239"
            "12547d1e8a3b5ed6"
            "e1bfd7097821233f"
            "a0538f3db854fee6";
        std::string output = Xale::Cryptography::SHA512::hashToString(
            "The quick brown fox jumps over the lazy dog");
        return expect == output;
    }

    // Different inputs must produce different hashes
    DECLARE_SHA512_TEST(different_inputs)
    {
        std::string h1 = Xale::Cryptography::SHA512::hashToString("abc");
        std::string h2 = Xale::Cryptography::SHA512::hashToString("abd");
        return h1 != h2;
    }

    // hashSize() returns 64
    DECLARE_SHA512_TEST(hash_size)
    {
        return Xale::Cryptography::SHA512::hashSize() == 64;
    }
}

#endif // SHA512_TEST_H
