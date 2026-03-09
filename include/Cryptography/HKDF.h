#ifndef CRYPTOGRAPHY_HKDF_H
#define CRYPTOGRAPHY_HKDF_H

#include "Cryptography/HMAC_SHA256.h"

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace Xale::Cryptography
{
    /**
     * @brief HKDF (HMAC-based Key Derivation Function)
     *        Uses HMAC-SHA256.
     */
    class HKDF
    {
        private:
            // Hash output size (SHA-256 = 32 bytes)
            static constexpr std::size_t _hashLen = 32;

        public:
            HKDF() = default;
            ~HKDF() = default;

            /**
             * @brief Derives a key (PRK) from input keying material.
             *        PRK = HMAC-SHA256(salt, IKM)
             * @param salt Optional salt
             * @param ikm  Input keying material
             * @return PRK as a 32-byte array
             */
            static std::array<std::uint8_t, _hashLen> extract(
                const std::uint8_t* salt, std::size_t saltLen,
                const std::uint8_t* ikm, std::size_t ikmLen);

            static std::array<std::uint8_t, _hashLen> extract(
                const std::vector<std::uint8_t>& salt,
                const std::vector<std::uint8_t>& ikm);

            /**
             * @brief Expands a PRK into output keying material of desired length.
             * @param prk Pseudorandom key 
             * @param info Optional context
             * @param length Desired output length in bytes
             * @return OKM as a byte vector of the requested length
             */
            static std::vector<std::uint8_t> expand(
                const std::uint8_t* prk, std::size_t prkLen,
                const std::uint8_t* info, std::size_t infoLen,
                std::size_t length);

            static std::vector<std::uint8_t> expand(
                const std::vector<std::uint8_t>& prk,
                const std::vector<std::uint8_t>& info,
                std::size_t length);

            // Info
            static constexpr std::size_t hashLen() { return _hashLen; }
    };
}

#endif // CRYPTOGRAPHY_HKDF_H
