#ifndef CRYPTOGRAPHY_SHA256
#define CRYPTOGRAPHY_SHA256

#include <array>
#include <string>
#include <cstddef>
#include <cstdint>

namespace Xale::Cryptography
{
    /**
     * @brief SHA256 implementation
     */
    class SHA256
    {
        private:
            // SHA-256 output size in bytes.
            static constexpr std::size_t outputSize = 32;
            // SHA-256 internal block size in bytes.
            static constexpr std::size_t blockSize = 64;
            // SHA-256 state size in bytes.
            static constexpr std::size_t stateSize = 8;

        public:
            SHA256();
            ~SHA256() = default;

            // Hash methods
            static std::array<std::uint8_t, outputSize> hash(const std::uint8_t* data, std::size_t len);
            static std::array<std::uint8_t, outputSize> hash(const std::string& text);
            static std::string hashToString(const std::uint8_t* data, std::size_t len);
            static std::string hashToString(const std::string& text); 

            // Info
            static constexpr std::size_t hashSize();
        
        private:
            // Core computing
            static std::array<std::uint32_t, stateSize> process(
                   const std::array<std::uint32_t, stateSize> state, 
                   const std::uint8_t block[blockSize]); 
            
            // Helpers
            static std::array<std::uint32_t, stateSize> initialState();
            static std::array<std::uint8_t, outputSize> stateToDigest(const std::array<std::uint32_t, stateSize>& state);
            static std::string toHex(const std::array<std::uint8_t, outputSize>& digest);
    };
}

#endif // CRYPTOGRAPHY_SHA256
