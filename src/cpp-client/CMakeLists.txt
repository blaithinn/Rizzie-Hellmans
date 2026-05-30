cmake_minimum_required(VERSION 3.16)
project(SecureChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CURL REQUIRED)

# libsodium
find_library(SODIUM_LIB sodium REQUIRED)
find_path(SODIUM_INCLUDE sodium.h PATH_SUFFIXES sodium)

include_directories(include ${SODIUM_INCLUDE})

add_executable(client
    src/main.cpp
    src/HttpClient.cpp
    src/CryptoUtils.cpp
)

target_link_libraries(client CURL::libcurl ${SODIUM_LIB})
