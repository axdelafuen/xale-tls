#include "Cryptography/AES128.h"

namespace Xale::Cryptography
{
    static inline std::uint8_t xtime(std::uint8_t a)
    {
        return static_cast<std::uint8_t>((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00));
    }

    static inline std::uint8_t gmul(std::uint8_t a, std::uint8_t b)
    {
        std::uint8_t result = 0;
        std::uint8_t temp = a;
        for (int i = 0; i < 8; ++i)
        {
            if (b & 1)
                result ^= temp;
            temp = xtime(temp);
            b >>= 1;
        }
        return result;
    }

    std::array<std::uint8_t, AES128::_expandedKeySize> AES128::expandKey(const std::uint8_t* key)
    {
        std::array<std::uint8_t, _expandedKeySize> roundKeys = {};

        // First round key is the key itself
        std::memcpy(roundKeys.data(), key, _keySize);

        // Generate remaining round keys (word by word, 4 bytes each)
        for (std::size_t i = _keySize; i < _expandedKeySize; i += 4)
        {
            std::uint8_t temp[4];
            std::memcpy(temp, &roundKeys[i - 4], 4);

            if (i % _keySize == 0)
            {
                // RotWord
                std::uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                // SubWord
                temp[0] = _sbox[temp[0]];
                temp[1] = _sbox[temp[1]];
                temp[2] = _sbox[temp[2]];
                temp[3] = _sbox[temp[3]];

                // XOR Rcon
                temp[0] ^= _rcon[i / _keySize - 1];
            }

            roundKeys[i    ] = roundKeys[i - _keySize    ] ^ temp[0];
            roundKeys[i + 1] = roundKeys[i - _keySize + 1] ^ temp[1];
            roundKeys[i + 2] = roundKeys[i - _keySize + 2] ^ temp[2];
            roundKeys[i + 3] = roundKeys[i - _keySize + 3] ^ temp[3];
        }

        return roundKeys;
    }

    void AES128::subBytes(std::array<std::uint8_t, _blockSize>& state)
    {
        for (auto& byte : state)
            byte = _sbox[byte];
    }

    void AES128::invSubBytes(std::array<std::uint8_t, _blockSize>& state)
    {
        for (auto& byte : state)
            byte = _invSbox[byte];
    }

    void AES128::shiftRows(std::array<std::uint8_t, _blockSize>& state)
    {
        // State is column-major: state[row + 4*col]
        // Row 0: no shift
        // Row 1: left shift by 1
        std::uint8_t t = state[1];
        state[1]  = state[5];
        state[5]  = state[9];
        state[9]  = state[13];
        state[13] = t;

        // Row 2: left shift by 2
        std::swap(state[2],  state[10]);
        std::swap(state[6],  state[14]);

        // Row 3: left shift by 3 (= right shift by 1)
        t = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7]  = state[3];
        state[3]  = t;
    }

    void AES128::invShiftRows(std::array<std::uint8_t, _blockSize>& state)
    {
        // Row 1: right shift by 1
        std::uint8_t t = state[13];
        state[13] = state[9];
        state[9]  = state[5];
        state[5]  = state[1];
        state[1]  = t;

        // Row 2: right shift by 2
        std::swap(state[2],  state[10]);
        std::swap(state[6],  state[14]);

        // Row 3: right shift by 3 (= left shift by 1)
        t = state[3];
        state[3]  = state[7];
        state[7]  = state[11];
        state[11] = state[15];
        state[15] = t;
    }

    void AES128::mixColumns(std::array<std::uint8_t, _blockSize>& state)
    {
        for (int col = 0; col < 4; ++col)
        {
            int i = col * 4;
            std::uint8_t a0 = state[i], a1 = state[i + 1], a2 = state[i + 2], a3 = state[i + 3];

            state[i    ] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
            state[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
            state[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
            state[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
        }
    }

    void AES128::invMixColumns(std::array<std::uint8_t, _blockSize>& state)
    {
        for (int col = 0; col < 4; ++col)
        {
            int i = col * 4;
            std::uint8_t a0 = state[i], a1 = state[i + 1], a2 = state[i + 2], a3 = state[i + 3];

            state[i    ] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
            state[i + 1] = gmul(a0, 9)  ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
            state[i + 2] = gmul(a0, 13) ^ gmul(a1, 9)  ^ gmul(a2, 14) ^ gmul(a3, 11);
            state[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9)  ^ gmul(a3, 14);
        }
    }

    void AES128::addRoundKey(std::array<std::uint8_t, _blockSize>& state, const std::uint8_t* roundKey)
    {
        for (std::size_t i = 0; i < _blockSize; ++i)
            state[i] ^= roundKey[i];
    }

    std::array<std::uint8_t, AES128::_blockSize> AES128::encrypt(
        const std::uint8_t* key,
        const std::uint8_t* plaintext)
    {
        auto roundKeys = expandKey(key);
        std::array<std::uint8_t, _blockSize> state;
        std::memcpy(state.data(), plaintext, _blockSize);

        addRoundKey(state, roundKeys.data());

        for (std::size_t round = 1; round < _numRounds; ++round)
        {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys.data() + round * _blockSize);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys.data() + _numRounds * _blockSize);

        return state;
    }

    std::array<std::uint8_t, AES128::_blockSize> AES128::encrypt(
        const std::array<std::uint8_t, _keySize>& key,
        const std::array<std::uint8_t, _blockSize>& plaintext)
    {
        return encrypt(key.data(), plaintext.data());
    }

    std::array<std::uint8_t, AES128::_blockSize> AES128::decrypt(
        const std::uint8_t* key,
        const std::uint8_t* ciphertext)
    {
        auto roundKeys = expandKey(key);
        std::array<std::uint8_t, _blockSize> state;
        std::memcpy(state.data(), ciphertext, _blockSize);

        addRoundKey(state, roundKeys.data() + _numRounds * _blockSize);

        for (std::size_t round = _numRounds - 1; round > 0; --round)
        {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys.data() + round * _blockSize);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys.data());

        return state;
    }

    std::array<std::uint8_t, AES128::_blockSize> AES128::decrypt(
        const std::array<std::uint8_t, _keySize>& key,
        const std::array<std::uint8_t, _blockSize>& ciphertext)
    {
        return decrypt(key.data(), ciphertext.data());
    }

    constexpr std::size_t AES128::blockSize()
    {
        return _blockSize;
    }

    constexpr std::size_t AES128::keySize()
    {
        return _keySize;
    }

    std::string AES128::toHex(const std::array<std::uint8_t, _blockSize>& block)
    {
        std::ostringstream oss;
        for (auto byte : block)
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        return oss.str();
    }
}
