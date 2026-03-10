cmake_minimum_required(VERSION 3.10)
project(XaleDb VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(EX_SRV_DIR ${CMAKE_SOURCE_DIR}/example/server)
set(EX_CLI_DIR ${CMAKE_SOURCE_DIR}/example/client)
set(TST_DIR ${CMAKE_SOURCE_DIR}/tests)

file(GLOB_RECURSE SOURCES "${SRC_DIR}/*.cpp")
file(GLOB_RECURSE SERVER "${EX_SRV_DIR}/*.cpp")
file(GLOB_RECURSE CLIENT "${EX_CLI_DIR}/*.cpp")
file(GLOB_RECURSE TESTS "${TST_DIR}/*.cpp")

# Core
add_library(xale-tls-core ${SOURCES})
target_include_directories(xale-tls-core PUBLIC ${INCLUDE_DIR})
#if(WIN32)
#    target_link_libraries(xale-tls-core PUBLIC ws2_32)
#endif()

# Example server
add_executable(xale-tls-server ${SERVER})
target_include_directories(xale-tls-server PRIVATE ${INCLUDE_DIR})
target_link_libraries(xale-tls-server PRIVATE xale-tls-core)

# Example client
add_executable(xale-tls-client ${CLIENT})
target_include_directories(xale-tls-client PRIVATE ${INCLUDE_DIR})
target_link_libraries(xale-tls-client PRIVATE xale-tls-core)

# Tests
add_executable(xale-tls-tests ${TESTS})
target_include_directories(xale-tls-tests PRIVATE ${INCLUDE_DIR})
target_link_libraries(xale-tls-tests PRIVATE xale-tls-core)

if(UNIX)
    target_compile_options(xale-tls-core PRIVATE -Wall -Wextra)
    target_compile_options(xale-tls-server PRIVATE -Wall -Wextra)
    target_compile_options(xale-tls-client PRIVATE -Wall -Wextra)
    target_compile_options(xale-tls-tests PRIVATE -Wall -Wextra)

endif()

