#include "TestsHelper.h"

#include <string>
#include <iostream>
#include <exception>

// Include all test files here
#include "Cryptography/SHA256Tests.h"
#include "Cryptography/HMAC_SHA256Tests.h"
#include "Cryptography/HKDFTests.h"
// ---

const std::string RED_COLOR = "\033[31m";
const std::string RESET = "\033[0m";

int main()
{
    using namespace Xale::Tests;

    auto& tests = TestRegistry::getTests();
    const size_t total = tests.size();
    int failed = 0;
    int passed = 0;

    std::cout << "------------------------------------" << std::endl;
    std::cout << "Running " << total << " test(s)..." << std::endl;
    std::cout << "------------------------------------" << std::endl;

	for (const auto& testPair : tests)
    {
        const std::string& testName = testPair.first;
        bool (*testFunc)() = testPair.second;
        try {
            if (!testFunc())
            {
                std::cout << RED_COLOR << "\t[FAIL] " << testName << RESET << std::endl;
                ++failed;
            }
            else
            {
                std::cout << "\t[PASS] " << testName << std::endl;
                ++passed;
            }
        }
        catch (const std::exception& e) {
            std::cout << RED_COLOR << "\t[FAIL] " << testName << " > " << e.what() << RESET << std::endl;
            ++failed;
		}
    }

    // Tests results
    std::cout << "------------------------------------" << std::endl;
    if (failed != 0 || passed + failed != total)
    {
        std::cout << failed << " test(s) failed (" << passed << "/" << total << " passed)" << std::endl;
        return 1;
    }

    std::cout << std::endl << "All tests passed (" << passed << "/" << total << " passed)" << std::endl;
    
    return 0;
}
