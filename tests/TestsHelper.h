#ifndef TESTS_HELPER_H
#define TESTS_HELPER_H

#include <string>
#include <vector>

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
}

#endif // TESTS_HELPER_H
