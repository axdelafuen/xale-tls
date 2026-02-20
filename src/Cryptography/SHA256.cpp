#include "Cryptography/SHA256.h"

namespace Xale::Cryptography
{
    /**
     * @brief TODO()
     * @param
     * @param
     * @return
     */
    std::array<std::uint8_t, SHA256::outputSize> SHA256::hash(const std::uint8_t* data, std::size_t len)
    {
        return {};
    }

    /**
     * @brief TODO()
     * @param
     * @param
     * @return
     */
    std::array<std::uint8_t, SHA256::outputSize> SHA256::hash(const std::string& text)
    {
        return {};
    }

    /**
     * @brief TODO()
     * @param
     * @return
     */
    std::string SHA256::hashToString(const std::uint8_t* data, std::size_t len)
    {
        return "";
    }
    
    /**
     * @brief TODO()
     * @param
     * @return
     */
    std::string SHA256::hashToString(const std::string& text)
    {
        return "";
    }

    /**
     * @brief Get the size of the SHA256 hash
     */
    constexpr std::size_t SHA256::hashSize()
    {
        return SHA256::outputSize; 
    }
}
