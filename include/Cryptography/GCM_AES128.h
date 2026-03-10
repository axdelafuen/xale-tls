#ifndef CRYPTOGRAPHY_GCM_AES128_H
#define CRYPTOGRAPHY_GCM_AES128_H

#include "Cryptography/AES128.h"
#include "Cryptography/GaloisFields.h"

#include <array>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <utility>
#include <cstring>
#include <algorithm>

namespace Xale::Cryptography
{
    /**
     * @brief AES-128-GCM (Galois/Counter Mode).
     */
    class GCM_AES128
    {
        private:
            static constexpr std::size_t _keySize = 16;
            static constexpr std::size_t _blockSize = 16;
            static constexpr std::size_t _tagSize = 16;

            using Block = std::array<std::uint8_t, _blockSize>;

        public:
            GCM_AES128() = default;
            ~GCM_AES128() = default;

            /**
             * @brief Authenticated encryption (GCM-AE, Algorithm 4 of NIST SP 800-38D).
             * @param key       128-bit encryption key.
             * @param iv        Initialization vector (typically 96 bits / 12 bytes).
             * @param aad       Additional authenticated data.
             * @param plaintext Data to encrypt.
             * @return Pair of (ciphertext, 128-bit authentication tag).
             */
            static std::pair<std::vector<std::uint8_t>, std::array<std::uint8_t, _tagSize>>
            encrypt(
                const std::array<std::uint8_t, _keySize>& key,
                const std::vector<std::uint8_t>& iv,
                const std::vector<std::uint8_t>& aad,
                const std::vector<std::uint8_t>& plaintext);

            /**
             * @brief Authenticated decryption (GCM-AD, Algorithm 5 of NIST SP 800-38D).
             * @param key        128-bit encryption key.
             * @param iv         Initialization vector (typically 96 bits / 12 bytes).
             * @param aad        Additional authenticated data.
             * @param ciphertext Data to decrypt.
             * @param tag        128-bit authentication tag to verify.
             * @return Decrypted plaintext, or std::nullopt if authentication fails.
             */
            static std::optional<std::vector<std::uint8_t>>
            decrypt(
                const std::array<std::uint8_t, _keySize>& key,
                const std::vector<std::uint8_t>& iv,
                const std::vector<std::uint8_t>& aad,
                const std::vector<std::uint8_t>& ciphertext,
                const std::array<std::uint8_t, _tagSize>& tag);

            // Info
            static constexpr std::size_t keySize() { return _keySize; }
            static constexpr std::size_t blockSize() { return _blockSize; }
            static constexpr std::size_t tagSize() { return _tagSize; }

        private:
            /**
             * @brief Compute initial counter block J0 (Section 7.1 of NIST SP 800-38D).
             */
            static Block computeJ0(
                const Block& H,
                const std::vector<std::uint8_t>& iv);

            /**
             * @brief GHASH function (Algorithm 2 of NIST SP 800-38D).
             * @param H    Hash sub-key (AES_K(0^128)).
             * @param data Input data, must be a multiple of 16 bytes.
             */
            static Block ghash(
                const Block& H,
                const std::vector<std::uint8_t>& data);

            /**
             * @brief GCTR function (Algorithm 3 of NIST SP 800-38D).
             * @param key  128-bit key for AES.
             * @param icb  Initial counter block.
             * @param data Input data (arbitrary length).
             */
            static std::vector<std::uint8_t> gctr(
                const std::array<std::uint8_t, _keySize>& key,
                const Block& icb,
                const std::vector<std::uint8_t>& data);

            /**
             * @brief Increment the rightmost 32 bits of the block (mod 2^32).
             */
            static Block inc32(const Block& block);

            /**
             * @brief Build the GHASH input: A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64.
             */
            static std::vector<std::uint8_t> buildGhashInput(
                const std::vector<std::uint8_t>& aad,
                const std::vector<std::uint8_t>& ciphertext);
    };
}

#endif // CRYPTOGRAPHY_GCM_AES128_H

