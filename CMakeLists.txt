cmake_minimum_required(VERSION 3.10)

project(FileEncryption VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

set(SOURCES
    lab2.c  # добавьте другие файлы, если они есть
)

add_executable(FileEncryption ${SOURCES})

target_link_libraries(FileEncryption OpenSSL::SSL OpenSSL::Crypto)

include_directories(${OPENSSL_INCLUDE_DIR})
