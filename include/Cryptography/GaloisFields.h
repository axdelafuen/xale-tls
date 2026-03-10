#ifndef CRYPTOGRAPHY_GALOIS_FIELDS_H
#define CRYPTOGRAPHY_GALOIS_FIELDS_H

#include <array>
#include <cstdint>
#include <cstddef>

namespace Xale::Cryptography
{
    /**
     * @brief Multiplication in GF(2^128) per NIST SP 800-38D, Algorithm 1.
     *
     * Reducing polynomial: x^128 + x^7 + x^2 + x + 1
     * (R = 0xE1 || 0^120)
     *
     * Bit ordering is MSB-first within each byte, matching the GCM specification.
     */
    inline std::array<std::uint8_t, 16> gf128Mul(
        const std::array<std::uint8_t, 16>& X,
        const std::array<std::uint8_t, 16>& Y)
    {
        std::array<std::uint8_t, 16> Z = {};  // Z_0 = 0^128
        std::array<std::uint8_t, 16> V = Y;   // V_0 = Y

        for (int i = 0; i < 128; ++i)
        {
            // Check bit i of X (MSB-first: bit 0 is the high bit of byte 0)
            if ((X[i / 8] >> (7 - (i % 8))) & 1)
            {
                for (int j = 0; j < 16; ++j)
                    Z[j] ^= V[j];
            }

            // Save LSB of V (bit 127)
            bool lsb = V[15] & 1;

            // Right-shift V by one bit
            for (int j = 15; j > 0; --j)
                V[j] = static_cast<std::uint8_t>((V[j] >> 1) | (V[j - 1] << 7));
            V[0] >>= 1;

            // If the discarded bit was 1, XOR with R
            if (lsb)
                V[0] ^= 0xE1;
        }

        return Z;
    }

    // TODO: GF(2^255 − 19) for X25519 / Ed25519
}

#endif // CRYPTOGRAPHY_GALOIS_FIELDS_H
