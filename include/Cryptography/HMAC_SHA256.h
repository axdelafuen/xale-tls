#ifndef CRYPTOGRAPHY_HMAC_SHA256_H
#define CRYPTOGRAPHY_HMAC_SHA256_H

#include <array>
#include <string>
#include <cstdint>

namespace Xale::Cryptography
{
    /**
     * @brief HMAC-SHA256 implementation
     */
    class HMAC_SHA256
    {
        private:
            /**
             * Consts
             */
            // HMAC-SHA256 output size in bytes.
            static constexpr std::size_t _outputSize = 32;
            // HMAC-SHA256 internal block size in bytes.
            static constexpr std::size_t _blockSize = 64;
            // HMAC-SHA256 ipad
	        static constexpr std::uint8_t _ipad = 0x36;
            // HMAC-SHA256 opad
            static constexpr std::uint8_t _opad = 0x5c;

        public:
            HMAC_SHA256() = default;
            ~HMAC_SHA256() = default;

            // Hash methods
            static std::array<std::uint8_t, _outputSize> mac(
                const std::uint8_t* key, std::size_t keyLen,
                const std::uint8_t* data, std::size_t dataLen);

            static std::array<std::uint8_t, _outputSize> mac(
                const std::string& key,
                const std::string& data);

            static std::string macToString(
                const std::uint8_t* key, std::size_t keyLen,
                const std::uint8_t* data, std::size_t dataLen);

            static std::string macToString(
                const std::string& key,
                const std::string& data);

            // Info
            static constexpr std::size_t macSize();

        private:
            // Core computing
            static std::array<std::uint8_t, _blockSize> deriveBlockKey(
                const std::uint8_t* key, std::size_t keyLen);
    };
}

#endif // CRYPTOGRAPHY_HMAC_SHA256_H
