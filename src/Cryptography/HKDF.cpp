#include "Cryptography/HKDF.h"

namespace Xale::Cryptography
{
    std::array<std::uint8_t, HKDF::_hashLen> HKDF::extract(
        const std::uint8_t* salt, std::size_t saltLen,
        const std::uint8_t* ikm, std::size_t ikmLen)
    {
        if (salt == nullptr || saltLen == 0)
        {
            std::array<std::uint8_t, _hashLen> zeroSalt = {};
            return HMAC_SHA256::mac(zeroSalt.data(), zeroSalt.size(), ikm, ikmLen);
        }

        return HMAC_SHA256::mac(salt, saltLen, ikm, ikmLen);
    }

    std::array<std::uint8_t, HKDF::_hashLen> HKDF::extract(
        const std::vector<std::uint8_t>& salt,
        const std::vector<std::uint8_t>& ikm)
    {
        return extract(salt.data(), salt.size(), ikm.data(), ikm.size());
    }

    std::vector<std::uint8_t> HKDF::expand(
        const std::uint8_t* prk, std::size_t prkLen,
        const std::uint8_t* info, std::size_t infoLen,
        std::size_t length)
    {
        if (length > 255 * _hashLen)
            throw std::invalid_argument("HKDF-Expand: requested length too large");

        std::size_t n = (length + _hashLen - 1) / _hashLen;

        std::vector<std::uint8_t> okm;
        okm.reserve(length);

        std::array<std::uint8_t, _hashLen> prev = {};
        std::size_t prevLen = 0;

        for (std::size_t i = 1; i <= n; ++i)
        {
            std::vector<std::uint8_t> input;
            input.reserve(prevLen + infoLen + 1);

            input.insert(input.end(), prev.data(), prev.data() + prevLen);
            if (infoLen > 0)
                input.insert(input.end(), info, info + infoLen);
            input.push_back(static_cast<std::uint8_t>(i));

            prev = HMAC_SHA256::mac(prk, prkLen, input.data(), input.size());
            prevLen = _hashLen;

            std::size_t remaining = length - okm.size();
            std::size_t toCopy = std::min(remaining, _hashLen);
            okm.insert(okm.end(), prev.begin(), prev.begin() + toCopy);
        }

        return okm;
    }

    std::vector<std::uint8_t> HKDF::expand(
        const std::vector<std::uint8_t>& prk,
        const std::vector<std::uint8_t>& info,
        std::size_t length)
    {
        return expand(prk.data(), prk.size(), info.data(), info.size(), length);
    }

}

