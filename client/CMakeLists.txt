cmake_minimum_required(VERSION 3.16)
project(KeyAuthClient VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_executable(KeyAuthClient
    src/main.cpp
    src/hwid.cpp
    src/api.cpp
    src/encryption.cpp
    src/utils.cpp
)

target_include_directories(KeyAuthClient PRIVATE src)
target_link_libraries(KeyAuthClient PRIVATE OpenSSL::SSL OpenSSL::Crypto libcurl)

# Windows specific
if(WIN32)
    target_link_libraries(KeyAuthClient PRIVATE winhttp crypt32)
    target_compile_definitions(KeyAuthClient PRIVATE _WIN32_WINNT=0x0A00)
endif()
