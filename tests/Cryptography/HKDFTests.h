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
    DECLARE_HKDF_TEST(extract_matches_hmac)
    {
        std::string salt = "xale";
        std::string ikm = "xale123";

        auto prk = Xale::Cryptography::HKDF::extract(
            reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(),
            reinterpret_cast<const std::uint8_t*>(ikm.data()), ikm.size());

        auto expected = Xale::Cryptography::HMAC_SHA256::mac(salt, ikm);

        return prk == expected;
    }

    DECLARE_HKDF_TEST(extract_empty_salt)
    {
        std::string ikm = "xale123";

        auto prk = Xale::Cryptography::HKDF::extract(
            nullptr, 0,
            reinterpret_cast<const std::uint8_t*>(ikm.data()), ikm.size());

        return prk.size() == Xale::Cryptography::HKDF::hashLen();
    }

    DECLARE_HKDF_TEST(extract_different_inputs)
    {
        std::string salt = "xale";
        std::string ikm1 = "xale123";
        std::string ikm2 = "xale456";

        auto prk1 = Xale::Cryptography::HKDF::extract(
            reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(),
            reinterpret_cast<const std::uint8_t*>(ikm1.data()), ikm1.size());

        auto prk2 = Xale::Cryptography::HKDF::extract(
            reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(),
            reinterpret_cast<const std::uint8_t*>(ikm2.data()), ikm2.size());

        return prk1 != prk2;
    }

    DECLARE_HKDF_TEST(expand_output_length)
    {
        std::string salt = "xale";
        std::string ikm = "xale123";
        std::string info = "test-context";

        auto prk = Xale::Cryptography::HKDF::extract(
            reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(),
            reinterpret_cast<const std::uint8_t*>(ikm.data()), ikm.size());

        auto okm = Xale::Cryptography::HKDF::expand(
            prk.data(), prk.size(),
            reinterpret_cast<const std::uint8_t*>(info.data()), info.size(),
            42);

        return okm.size() == 42;
    }

    DECLARE_HKDF_TEST(expand_deterministic)
    {
        std::string salt = "xale";
        std::string ikm = "xale123";
        std::string info = "test-context";

        auto prk = Xale::Cryptography::HKDF::extract(
            reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(),
            reinterpret_cast<const std::uint8_t*>(ikm.data()), ikm.size());

        auto okm1 = Xale::Cryptography::HKDF::expand(
            prk.data(), prk.size(),
            reinterpret_cast<const std::uint8_t*>(info.data()), info.size(),
            64);

        auto okm2 = Xale::Cryptography::HKDF::expand(
            prk.data(), prk.size(),
            reinterpret_cast<const std::uint8_t*>(info.data()), info.size(),
            64);

        return okm1 == okm2;
    }

    DECLARE_HKDF_TEST(expand_different_info)
    {
        std::string salt = "xale";
        std::string ikm = "xale123";
        std::string info1 = "context-a";
        std::string info2 = "context-b";

        auto prk = Xale::Cryptography::HKDF::extract(
            reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(),
            reinterpret_cast<const std::uint8_t*>(ikm.data()), ikm.size());

        auto okm1 = Xale::Cryptography::HKDF::expand(
            prk.data(), prk.size(),
            reinterpret_cast<const std::uint8_t*>(info1.data()), info1.size(),
            32);

        auto okm2 = Xale::Cryptography::HKDF::expand(
            prk.data(), prk.size(),
            reinterpret_cast<const std::uint8_t*>(info2.data()), info2.size(),
            32);

        return okm1 != okm2;
    }
}

#endif // HKDF_TEST_H
