cmake_minimum_required(VERSION 4.3)
project(AES_Steganography)

set(CMAKE_CXX_STANDARD 20)

add_executable(AES_Steganography main.cpp
        stb_image.h
        stb_image_write.h)

find_package(OpenSSL REQUIRED)

target_link_libraries(AES_Steganography PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)
