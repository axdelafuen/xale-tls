#ifndef TESTS_HELPER_H
#define TESTS_HELPER_H

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

namespace Xale::Tests 
{
    struct TestRegistry {
        static std::vector<std::pair<std::string, bool(*)()>>& getTests() {
            static std::vector<std::pair<std::string, bool(*)()>> tests;
            return tests;
        }
    };

    struct TestRegistrar {
        TestRegistrar(const char* category, const char* name, bool(*func)()) {
            std::string fullName = std::string("[") + category + "]" + name;
            TestRegistry::getTests().push_back({ fullName, func });
        }
    };

#define DECLARE_TEST(category, name) \
    bool test_##name(); \
    static TestRegistrar registrar_##name(#category, #name, test_##name); \
    bool test_##name()

    // Hex helpers
    static std::vector<std::uint8_t> hexToBytes(const std::string& hex)
    {
        std::vector<std::uint8_t> bytes;
        for (std::size_t i = 0; i < hex.size(); i += 2)
            bytes.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        return bytes;
    }

    static std::string bytesToHex(const std::uint8_t* data, std::size_t len)
    {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        for (std::size_t i = 0; i < len; ++i)
        {
            result.push_back(hex[data[i] >> 4]);
            result.push_back(hex[data[i] & 0x0F]);
        }
        return result;
    }
}

#endif // TESTS_HELPER_H
