#include "Cryptography/HMAC_SHA256.h"
#include "Cryptography/SHA256.h"

#include <cstring>
#include <vector>

namespace Xale::Cryptography
{
    std::array<std::uint8_t, HMAC_SHA256::_blockSize> HMAC_SHA256::deriveBlockKey(
        const std::uint8_t* key, std::size_t keyLen)
    {
        std::array<std::uint8_t, _blockSize> paddedKey = {};

        if (keyLen > _blockSize)
        {
            auto hashed = SHA256::hash(key, keyLen);
            std::memcpy(paddedKey.data(), hashed.data(), hashed.size());
        }
        else
        {
            std::memcpy(paddedKey.data(), key, keyLen);
        }

        return paddedKey;
    }

    std::array<std::uint8_t, HMAC_SHA256::_outputSize> HMAC_SHA256::mac(
        const std::uint8_t* key, std::size_t keyLen,
        const std::uint8_t* data, std::size_t dataLen)
    {
        auto paddedKey = deriveBlockKey(key, keyLen);

        std::vector<std::uint8_t> innerBuf(_blockSize + dataLen);
        for (std::size_t i = 0; i < _blockSize; ++i)
            innerBuf[i] = paddedKey[i] ^ _ipad;
        std::memcpy(innerBuf.data() + _blockSize, data, dataLen);

        auto innerHash = SHA256::hash(innerBuf.data(), innerBuf.size());

        std::array<std::uint8_t, _blockSize + _outputSize> outerBuf = {};
        for (std::size_t i = 0; i < _blockSize; ++i)
            outerBuf[i] = paddedKey[i] ^ _opad;
        std::memcpy(outerBuf.data() + _blockSize, innerHash.data(), _outputSize);

        return SHA256::hash(outerBuf.data(), outerBuf.size());
    }

    std::array<std::uint8_t, HMAC_SHA256::_outputSize> HMAC_SHA256::mac(
        const std::string& key,
        const std::string& data)
    {
        return mac(
            reinterpret_cast<const std::uint8_t*>(key.data()), key.size(),
            reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    }

    std::string HMAC_SHA256::macToString(
        const std::uint8_t* key, std::size_t keyLen,
        const std::uint8_t* data, std::size_t dataLen)
    {
        auto digest = mac(key, keyLen, data, dataLen);
        return SHA256::toHex(digest);
    }

    std::string HMAC_SHA256::macToString(
        const std::string& key,
        const std::string& data)
    {
        auto digest = mac(key, data);
        return SHA256::toHex(digest);
    }

    constexpr std::size_t HMAC_SHA256::macSize()
    {
        return _outputSize;
    }
}
