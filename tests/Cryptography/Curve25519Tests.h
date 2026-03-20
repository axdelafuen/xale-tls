#ifndef CURVE25519_TEST_H
#define CURVE25519_TEST_H

#include "Cryptography/Curve25519.h"
#include <string>
#include <cstdint>
#include <array>

#define DECLARE_CURVE25519_TEST(name) DECLARE_TEST(CRYPTO, curve25519_##name)

namespace Xale::Tests
{
    // RFC 7748 §6.1 — First test vector
    // Scalar:   a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
    // u-coord:  e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
    // Output:   c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
    DECLARE_CURVE25519_TEST(rfc7748_vector1)
    {
        auto scalar = hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        auto point  = hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        std::string expect = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

        auto result = Xale::Cryptography::Curve25519::x25519(scalar.data(), point.data());

        return bytesToHex(result.data(), result.size()) == expect;
    }

    // RFC 7748 §6.1 — Second test vector
    // Scalar:   4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
    // u-coord:  e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
    // Output:   95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957
    DECLARE_CURVE25519_TEST(rfc7748_vector2)
    {
        auto scalar = hexToBytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        auto point  = hexToBytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        std::string expect = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";

        auto result = Xale::Cryptography::Curve25519::x25519(scalar.data(), point.data());

        return bytesToHex(result.data(), result.size()) == expect;
    }

    // RFC 7748 §6.1 — Iterated test: 1 iteration
    // Start with k = u = basepoint (9)
    // After 1 iteration:  0900...00 × 0900...00  →  422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
    DECLARE_CURVE25519_TEST(rfc7748_iter1)
    {
        std::array<std::uint8_t, 32> k = {};
        k[0] = 9;
        std::string expect = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";

        auto result = Xale::Cryptography::Curve25519::x25519(k.data(), k.data());

        return bytesToHex(result.data(), result.size()) == expect;
    }

    // RFC 7748 §6.1 — Iterated test: 1000 iterations
    DECLARE_CURVE25519_TEST(rfc7748_iter1000)
    {
        std::array<std::uint8_t, 32> k = {};
        std::array<std::uint8_t, 32> u = {};
        k[0] = 9;
        u[0] = 9;
        std::string expect = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";

        for (int i = 0; i < 1000; ++i)
        {
            auto result = Xale::Cryptography::Curve25519::x25519(k.data(), u.data());
            u = k;
            k = result;
        }

        return bytesToHex(k.data(), k.size()) == expect;
    }

    // x25519Base: scalar × base-point (9)
    // Using first iter vector: x25519Base(09 00..00) should equal the 1-iteration result
    DECLARE_CURVE25519_TEST(x25519_base)
    {
        std::array<std::uint8_t, 32> scalar = {};
        scalar[0] = 9;
        std::string expect = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";

        auto result = Xale::Cryptography::Curve25519::x25519Base(scalar.data());

        return bytesToHex(result.data(), result.size()) == expect;
    }

    // Array-overload variant of x25519
    DECLARE_CURVE25519_TEST(x25519_array_overload)
    {
        auto scalarVec = hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        auto pointVec  = hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        std::string expect = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

        std::array<std::uint8_t, 32> scalar, point;
        std::copy(scalarVec.begin(), scalarVec.end(), scalar.begin());
        std::copy(pointVec.begin(), pointVec.end(), point.begin());

        auto result = Xale::Cryptography::Curve25519::x25519(scalar, point);

        return bytesToHex(result.data(), result.size()) == expect;
    }

    // scalarSize() returns 32
    DECLARE_CURVE25519_TEST(scalar_size)
    {
        return Xale::Cryptography::Curve25519::scalarSize() == 32;
    }

    // pointSize() returns 32
    DECLARE_CURVE25519_TEST(point_size)
    {
        return Xale::Cryptography::Curve25519::pointSize() == 32;
    }
}

#endif // CURVE25519_TEST_H
