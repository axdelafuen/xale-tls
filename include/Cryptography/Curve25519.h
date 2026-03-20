#ifndef CRYPTOGRAPHY_CURVE25519_H
#define CRYPTOGRAPHY_CURVE25519_H

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>

namespace Xale::Cryptography
{
    /**
     * @brief X25519 Elliptic-Curve Diffie-Hellman key exchange.
     *        Arithmetic on Curve25519 over GF(2^255 - 19).
     *        Reference: RFC 7748.
     */
    class Curve25519
    {
        private:
            static constexpr std::size_t _scalarSize = 32;
            static constexpr std::size_t _pointSize  = 32;

            // ---------- field element: 256-bit stored as 5 × 51-bit limbs ----------
            struct Fe
            {
                std::uint64_t v[5];
            };

            // Field arithmetic over GF(2^255 - 19)
            static Fe feZero();
            static Fe feOne();
            static Fe feFromBytes(const std::uint8_t in[32]);
            static void feToBytes(std::uint8_t out[32], const Fe& f);

            static Fe feAdd(const Fe& a, const Fe& b);
            static Fe feSub(const Fe& a, const Fe& b);
            static Fe feMul(const Fe& a, const Fe& b);
            static Fe feSquare(const Fe& a);
            static Fe feInvert(const Fe& z);

            // Scalar clamping (RFC 7748 §5)
            static void clampScalar(std::uint8_t s[32]);

        public:
            Curve25519() = default;
            ~Curve25519() = default;

            /**
             * @brief X25519 scalar multiplication: scalar × point.
             * @param scalar  32-byte scalar (will be clamped internally)
             * @param point   32-byte u-coordinate of the input point
             * @return 32-byte u-coordinate of the resulting point
             */
            static std::array<std::uint8_t, _pointSize> x25519(
                const std::uint8_t* scalar,
                const std::uint8_t* point);

            static std::array<std::uint8_t, _pointSize> x25519(
                const std::array<std::uint8_t, _scalarSize>& scalar,
                const std::array<std::uint8_t, _pointSize>& point);

            /**
             * @brief X25519 base-point multiplication: scalar × 9 (base point).
             * @param scalar  32-byte scalar (will be clamped internally)
             * @return 32-byte public key (u-coordinate)
             */
            static std::array<std::uint8_t, _pointSize> x25519Base(
                const std::uint8_t* scalar);

            static std::array<std::uint8_t, _pointSize> x25519Base(
                const std::array<std::uint8_t, _scalarSize>& scalar);

            // Info
            static constexpr std::size_t scalarSize() { return _scalarSize; }
            static constexpr std::size_t pointSize()  { return _pointSize; }

            // Utility
            static std::string toHex(const std::array<std::uint8_t, _pointSize>& data);
    };
}

#endif // CRYPTOGRAPHY_CURVE25519_H