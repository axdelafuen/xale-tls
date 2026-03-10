#include "Cryptography/SHA512.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace Xale::Cryptography
{
    static inline uint64_t rotr64(uint64_t x, uint64_t n)
    {
        return (x >> n) | (x << (64 - n));
    }

    static inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z)
    {
        return (x & y) ^ (~x & z);
    }

    static inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static inline uint64_t bigSigma0(uint64_t x)
    {
        return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
    }

    static inline uint64_t bigSigma1(uint64_t x)
    {
        return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
    }

    static inline uint64_t smallSigma0(uint64_t x)
    {
        return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
    }

    static inline uint64_t smallSigma1(uint64_t x)
    {
        return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
    }

    std::array<std::uint64_t, SHA512::_stateSize> SHA512::initialState()
    {
        return {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
    }

    std::array<std::uint64_t, SHA512::_stateSize> SHA512::process(
            const std::array<std::uint64_t, _stateSize> state,
            const std::uint8_t block[blockSize])
    {
        uint64_t W[80];

        // Prepare message schedule (16 words from block, then extend to 80)
        for (int i = 0; i < 16; ++i)
        {
            W[i] = (static_cast<uint64_t>(block[i * 8    ]) << 56)
                  | (static_cast<uint64_t>(block[i * 8 + 1]) << 48)
                  | (static_cast<uint64_t>(block[i * 8 + 2]) << 40)
                  | (static_cast<uint64_t>(block[i * 8 + 3]) << 32)
                  | (static_cast<uint64_t>(block[i * 8 + 4]) << 24)
                  | (static_cast<uint64_t>(block[i * 8 + 5]) << 16)
                  | (static_cast<uint64_t>(block[i * 8 + 6]) <<  8)
                  | (static_cast<uint64_t>(block[i * 8 + 7]));
        }

        for (int i = 16; i < 80; ++i)
            W[i] = smallSigma1(W[i - 2]) + W[i - 7] + smallSigma0(W[i - 15]) + W[i - 16];

        uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 80; ++i)
        {
            uint64_t t1 = h + bigSigma1(e) + ch(e, f, g) + _K[i] + W[i];
            uint64_t t2 = bigSigma0(a) + maj(a, b, c);
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

    std::array<std::uint8_t, SHA512::_outputSize> SHA512::stateToDigest(
            const std::array<std::uint64_t, _stateSize>& state)
    {
        std::array<std::uint8_t, _outputSize> digest;
        for (int i = 0; i < 8; ++i)
        {
            digest[i * 8    ] = static_cast<uint8_t>(state[i] >> 56);
            digest[i * 8 + 1] = static_cast<uint8_t>(state[i] >> 48);
            digest[i * 8 + 2] = static_cast<uint8_t>(state[i] >> 40);
            digest[i * 8 + 3] = static_cast<uint8_t>(state[i] >> 32);
            digest[i * 8 + 4] = static_cast<uint8_t>(state[i] >> 24);
            digest[i * 8 + 5] = static_cast<uint8_t>(state[i] >> 16);
            digest[i * 8 + 6] = static_cast<uint8_t>(state[i] >>  8);
            digest[i * 8 + 7] = static_cast<uint8_t>(state[i]);
        }
        return digest;
    }

    std::string SHA512::toHex(const std::array<std::uint8_t, _outputSize>& digest)
    {
        std::ostringstream oss;
        for (auto byte : digest)
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        return oss.str();
    }

    std::array<std::uint8_t, SHA512::_outputSize> SHA512::hash(
            const std::uint8_t* data,
            std::size_t len)
    {
        auto state = initialState();

        // Process complete 128-byte blocks
        std::size_t i = 0;
        for (; i + blockSize <= len; i += blockSize)
            state = process(state, data + i);

        // Padding: remaining bytes + 0x80 + zeros + 128-bit big-endian length
        std::uint8_t buffer[256] = {};
        std::size_t remaining = len - i;
        std::memcpy(buffer, data + i, remaining);
        buffer[remaining] = 0x80;

        // If remaining < 112 bytes, pad fits in one block; otherwise two blocks
        std::size_t paddedLen = (remaining < 112) ? 128 : 256;

        // SHA-512 uses a 128-bit message length; we only support up to 2^64-1 bits
        // so the high 64 bits are always zero for practical inputs.
        uint64_t bitLen = static_cast<uint64_t>(len) * 8;
        // High 64 bits = 0 (already zeroed)
        // Low 64 bits at the very end
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

    std::array<std::uint8_t, SHA512::_outputSize> SHA512::hash(const std::string& text)
    {
        return hash(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    }

    std::string SHA512::hashToString(const std::uint8_t* data, std::size_t len)
    {
        return toHex(hash(data, len));
    }

    std::string SHA512::hashToString(const std::string& text)
    {
        return toHex(hash(text));
    }

}
