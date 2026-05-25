cmake_minimum_required(VERSION 3.16)
project(SecureChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CURL REQUIRED)

include_directories(include)

add_executable(client src/main.cpp src/HttpClient.cpp)

target_link_libraries(client CURL::libcurl)
