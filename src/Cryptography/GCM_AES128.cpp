#include "Cryptography/GCM_AES128.h"

namespace Xale::Cryptography
{
    GCM_AES128::Block GCM_AES128::inc32(const Block& block)
    {
        Block result = block;
        for (int i = 15; i >= 12; --i)
        {
            if (++result[i] != 0)
                break;
        }
        return result;
    }

    GCM_AES128::Block GCM_AES128::ghash(
        const Block& H,
        const std::vector<std::uint8_t>& data)
    {
        Block Y = {};
        for (std::size_t i = 0; i < data.size(); i += _blockSize)
        {
            for (std::size_t j = 0; j < _blockSize; ++j)
                Y[j] ^= data[i + j];
            Y = gf128Mul(Y, H);
        }
        return Y;
    }

    std::vector<std::uint8_t> GCM_AES128::gctr(
        const std::array<std::uint8_t, _keySize>& key,
        const Block& icb,
        const std::vector<std::uint8_t>& data)
    {
        if (data.empty())
            return {};

        std::vector<std::uint8_t> result(data.size());
        Block cb = icb;

        const std::size_t fullBlocks = data.size() / _blockSize;
        const std::size_t remaining  = data.size() % _blockSize;

        for (std::size_t i = 0; i < fullBlocks; ++i)
        {
            Block encrypted = AES128::encrypt(key, cb);
            for (std::size_t j = 0; j < _blockSize; ++j)
                result[i * _blockSize + j] = data[i * _blockSize + j] ^ encrypted[j];
            cb = inc32(cb);
        }

        if (remaining > 0)
        {
            Block encrypted = AES128::encrypt(key, cb);
            for (std::size_t j = 0; j < remaining; ++j)
                result[fullBlocks * _blockSize + j] =
                    data[fullBlocks * _blockSize + j] ^ encrypted[j];
        }

        return result;
    }

    GCM_AES128::Block GCM_AES128::computeJ0(
        const Block& H,
        const std::vector<std::uint8_t>& iv)
    {
        Block J0 = {};

        if (iv.size() == 12)
        {
            // J0 = IV || 0^31 || 1
            std::memcpy(J0.data(), iv.data(), 12);
            J0[15] = 0x01;
        }
        else
        {
            // J0 = GHASH_H( IV || 0^(s+64) || [len(IV)]_64 )
            // where s = 128·⌈len(IV)/128⌉ − len(IV) (in bits)
            const std::size_t ivPadded = ((iv.size() + 15) / 16) * 16;
            std::vector<std::uint8_t> ghashInput(ivPadded + 16, 0);
            std::memcpy(ghashInput.data(), iv.data(), iv.size());

            // Last 8 bytes: bit-length of IV as big-endian uint64
            const std::uint64_t ivBitLen = static_cast<std::uint64_t>(iv.size()) * 8;
            for (int i = 0; i < 8; ++i)
                ghashInput[ivPadded + 8 + i] =
                    static_cast<std::uint8_t>(ivBitLen >> (56 - 8 * i));

            J0 = ghash(H, ghashInput);
        }

        return J0;
    }

    std::vector<std::uint8_t> GCM_AES128::buildGhashInput(
        const std::vector<std::uint8_t>& aad,
        const std::vector<std::uint8_t>& ciphertext)
    {
        const std::size_t aadPadded = ((aad.size() + 15) / 16) * 16;
        const std::size_t ctPadded  = ((ciphertext.size() + 15) / 16) * 16;

        std::vector<std::uint8_t> input(aadPadded + ctPadded + 16, 0);

        if (!aad.empty())
            std::memcpy(input.data(), aad.data(), aad.size());

        if (!ciphertext.empty())
            std::memcpy(input.data() + aadPadded, ciphertext.data(), ciphertext.size());

        // Append bit-lengths as big-endian 64-bit integers
        const std::uint64_t aadBitLen = static_cast<std::uint64_t>(aad.size()) * 8;
        const std::uint64_t ctBitLen  = static_cast<std::uint64_t>(ciphertext.size()) * 8;
        const std::size_t offset = aadPadded + ctPadded;

        for (int i = 0; i < 8; ++i)
        {
            input[offset + i]     = static_cast<std::uint8_t>(aadBitLen >> (56 - 8 * i));
            input[offset + 8 + i] = static_cast<std::uint8_t>(ctBitLen  >> (56 - 8 * i));
        }

        return input;
    }

    std::pair<std::vector<std::uint8_t>, std::array<std::uint8_t, GCM_AES128::_tagSize>>
    GCM_AES128::encrypt(
        const std::array<std::uint8_t, _keySize>& key,
        const std::vector<std::uint8_t>& iv,
        const std::vector<std::uint8_t>& aad,
        const std::vector<std::uint8_t>& plaintext)
    {
        // H = AES_K(0^128)
        const Block zeroBlock = {};
        const Block H = AES128::encrypt(key, zeroBlock);

        // J0
        const Block J0 = computeJ0(H, iv);

        // C = GCTR_K(inc32(J0), P)
        auto ciphertext = gctr(key, inc32(J0), plaintext);

        // S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
        const auto ghashInput = buildGhashInput(aad, ciphertext);
        const Block S = ghash(H, ghashInput);

        // T = MSB_t( GCTR_K(J0, S) )
        const std::vector<std::uint8_t> sVec(S.begin(), S.end());
        const auto tagVec = gctr(key, J0, sVec);

        std::array<std::uint8_t, _tagSize> tag;
        std::memcpy(tag.data(), tagVec.data(), _tagSize);

        return {std::move(ciphertext), tag};
    }

    std::optional<std::vector<std::uint8_t>>
    GCM_AES128::decrypt(
        const std::array<std::uint8_t, _keySize>& key,
        const std::vector<std::uint8_t>& iv,
        const std::vector<std::uint8_t>& aad,
        const std::vector<std::uint8_t>& ciphertext,
        const std::array<std::uint8_t, _tagSize>& tag)
    {
        // H = AES_K(0^128)
        const Block zeroBlock = {};
        const Block H = AES128::encrypt(key, zeroBlock);

        // J0
        const Block J0 = computeJ0(H, iv);

        // P = GCTR_K(inc32(J0), C)
        auto plaintext = gctr(key, inc32(J0), ciphertext);

        // S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
        const auto ghashInput = buildGhashInput(aad, ciphertext);
        const Block S = ghash(H, ghashInput);

        // T' = MSB_t( GCTR_K(J0, S) )
        const std::vector<std::uint8_t> sVec(S.begin(), S.end());
        const auto computedTagVec = gctr(key, J0, sVec);

        // constant-time tag comparison
        std::uint8_t diff = 0;
        for (std::size_t i = 0; i < _tagSize; ++i)
            diff |= tag[i] ^ computedTagVec[i];

        if (diff != 0)
            return std::nullopt;

        return plaintext;
    }
}


