#include "Cryptography/SHA256.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace Xale::Cryptography
{
    static inline uint32_t rotr(uint32_t x, uint32_t n)
    {
        return (x >> n) | (x << (32 - n));
    }

    static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (~x & z);
    }

    static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static inline uint32_t bigSigma0(uint32_t x)
    {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static inline uint32_t bigSigma1(uint32_t x)
    {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static inline uint32_t smallSigma0(uint32_t x)
    {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static inline uint32_t smallSigma1(uint32_t x)
    {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    std::array<std::uint32_t, SHA256::_stateSize> SHA256::initialState()
    {
        return {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
    }

    std::array<std::uint32_t, SHA256::_stateSize> SHA256::process(
            const std::array<std::uint32_t, _stateSize> state,
            const std::uint8_t block[blockSize])
    {
        uint32_t W[64];

        for (int i = 0; i < 16; ++i)
        {
            W[i] = (static_cast<uint32_t>(block[i * 4    ]) << 24)
                  | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
                  | (static_cast<uint32_t>(block[i * 4 + 2]) <<  8)
                  | (static_cast<uint32_t>(block[i * 4 + 3]));
        }

        for (int i = 16; i < 64; ++i)
            W[i] = smallSigma1(W[i - 2]) + W[i - 7] + smallSigma0(W[i - 15]) + W[i - 16];

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i)
        {
            uint32_t t1 = h + bigSigma1(e) + ch(e, f, g) + _K[i] + W[i];
            uint32_t t2 = bigSigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        return {
            state[0] + a, state[1] + b, state[2] + c, state[3] + d,
            state[4] + e, state[5] + f, state[6] + g, state[7] + h
        };
    }

    std::array<std::uint8_t, SHA256::_outputSize> SHA256::stateToDigest(
            const std::array<std::uint32_t, _stateSize>& state)
    {
        std::array<std::uint8_t, _outputSize> digest;
        for (int i = 0; i < 8; ++i)
        {
            digest[i * 4    ] = static_cast<uint8_t>(state[i] >> 24);
            digest[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            digest[i * 4 + 2] = static_cast<uint8_t>(state[i] >>  8);
            digest[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
        return digest;
    }

    std::string SHA256::toHex(const std::array<std::uint8_t, _outputSize>& digest)
    {
        std::ostringstream oss;
        for (auto byte : digest)
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        return oss.str();
    }

    std::array<std::uint8_t, SHA256::_outputSize> SHA256::hash(
            const std::uint8_t* data,
            std::size_t len)
    {
        auto state = initialState();

        std::size_t i = 0;
        for (; i + blockSize <= len; i += blockSize)
            state = process(state, data + i);

        std::uint8_t buffer[128] = {};
        std::size_t remaining = len - i;
        std::memcpy(buffer, data + i, remaining);
        buffer[remaining] = 0x80;

        std::size_t paddedLen = (remaining < 56) ? 64 : 128;

        uint64_t bitLen = static_cast<uint64_t>(len) * 8;
        buffer[paddedLen - 8] = static_cast<uint8_t>(bitLen >> 56);
        buffer[paddedLen - 7] = static_cast<uint8_t>(bitLen >> 48);
        buffer[paddedLen - 6] = static_cast<uint8_t>(bitLen >> 40);
        buffer[paddedLen - 5] = static_cast<uint8_t>(bitLen >> 32);
        buffer[paddedLen - 4] = static_cast<uint8_t>(bitLen >> 24);
        buffer[paddedLen - 3] = static_cast<uint8_t>(bitLen >> 16);
        buffer[paddedLen - 2] = static_cast<uint8_t>(bitLen >>  8);
        buffer[paddedLen - 1] = static_cast<uint8_t>(bitLen);

        for (std::size_t j = 0; j < paddedLen; j += blockSize)
            state = process(state, buffer + j);

        return stateToDigest(state);
    }

    std::array<std::uint8_t, SHA256::_outputSize> SHA256::hash(const std::string& text)
    {
        return hash(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    }

    std::string SHA256::hashToString(const std::uint8_t* data, std::size_t len)
    {
        return toHex(hash(data, len));
    }

    std::string SHA256::hashToString(const std::string& text)
    {
        return toHex(hash(text));
    }

    constexpr std::size_t SHA256::hashSize()
    {
        return _outputSize;
    }
}

