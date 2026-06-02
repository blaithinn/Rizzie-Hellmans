cmake_minimum_required(VERSION 3.16)
project(SecureChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CURL REQUIRED)

# libsodium — prefer the 1.0.19 build installed to /usr/local over the Ubuntu
# 24.04 apt package (1.0.18) which lacks crypto_kdf_hkdf_sha256_* APIs.
find_library(SODIUM_LIB sodium HINTS /usr/local/lib REQUIRED)
find_path(SODIUM_INCLUDE sodium.h HINTS /usr/local/include PATH_SUFFIXES sodium)

include_directories(include ${SODIUM_INCLUDE})

add_executable(client
    src/main.cpp
    src/Client.cpp
    src/HttpClient.cpp
    src/CryptoUtils.cpp
    src/KeyStore.cpp
    src/MessageStore.cpp
)

target_link_libraries(client CURL::libcurl ${SODIUM_LIB})
