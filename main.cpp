#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

const int SALT_LEN      = 16;
const int NONCE_LEN     = 12;
const int TAG_LEN       = 16;
const int KEY_LEN       = 32;
const int PBKDF2_ITERS  = 200000;

[[noreturn]] void openssl_error(const std::string& message) {
    unsigned long error = ERR_get_error();
    char buf[256];
    ERR_error_string_n(error, buf, sizeof(buf));
    throw std::runtime_error(message);
}

std::vector<uint8_t> createKey(const std::string& password, const uint8_t* salt) {
    std::vector<uint8_t> key(KEY_LEN);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.length(), salt, SALT_LEN, PBKDF2_ITERS, EVP_sha256(), KEY_LEN, key.data()) != 1) {
        openssl_error("PKCS5_PBKDF2_HMAC key failed");
    }
    return key;
}

std::vector<uint8_t> encrypt(const std::string& plaintext, const std::string& password) {
    std::vector<uint8_t> salt(SALT_LEN), nonce(NONCE_LEN);

    if (RAND_bytes(salt.data(), SALT_LEN) != 1) {
        openssl_error("RAND_bytes failed");
    }
    if (RAND_bytes(nonce.data(), NONCE_LEN) != 1) {
        openssl_error("RAND_bytes failed");
    }

    std::vector<uint8_t> key = createKey(password, salt.data());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        openssl_error("EVP_CIPHER_CTX_new failed");
    }

    std::vector<uint8_t> ciphertext(plaintext.length());
    std::vector<uint8_t> tag(TAG_LEN);

    int outLength = 0, totalLength = 0;

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            openssl_error("EVP_EncryptInit_ex (cipher) failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1) {
            openssl_error("Set IV failed");
        }
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
            openssl_error("EVP_EncryptInit_ex (key) failed");
        }

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLength, reinterpret_cast<const uint8_t*>(plaintext.data()), (int)plaintext.length()) != 1) {
            openssl_error("EVP_EncryptUpdate failed");
        }
        totalLength = outLength;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + totalLength, &outLength) != 1) {
            openssl_error("EVP_EncryptFinal_ex failed");
        }
        totalLength += outLength;
        ciphertext.resize(totalLength);

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1) {
            openssl_error("EVP_CIPHER_CTX_ctrl (tag) failed");
        }
    }
    catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> payload;
    payload.reserve(SALT_LEN + NONCE_LEN + TAG_LEN + ciphertext.size());
    payload.insert(payload.end(), salt.begin(), salt.end());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), tag.begin(), tag.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
    return payload;
}

std::string decrypt(const std::vector<uint8_t>& payload, const std::string& password) {

    if (payload.size() < (size_t)(SALT_LEN + NONCE_LEN + TAG_LEN)) {
        throw std::runtime_error("decrypt payload too small");
    }

    const uint8_t* salt         = payload.data();
    const uint8_t* nonce        = payload.data() + SALT_LEN;
    const uint8_t* tag          = payload.data() + SALT_LEN + NONCE_LEN;
    const uint8_t* ciphertext   = payload.data() + SALT_LEN + NONCE_LEN + TAG_LEN;

    size_t ciphertextLength = payload.size() - SALT_LEN - NONCE_LEN - TAG_LEN;
    std::vector<uint8_t> key = createKey(password, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        openssl_error("EVP_CIPHER_CTX_new failed");
    }

    std::vector<uint8_t> plaintext(ciphertextLength);
    int outLength = 0, totalLength = 0;
    int finalResultLength = 0;

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            openssl_error("EVP_DecryptInit_ex (cipher) failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1) {
            openssl_error("EVP_CIPHER_CTX_ctrl (IVLEN) failed");
        }
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) {
            openssl_error("EVP_DecryptInit_ex (key) failed");
        }

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLength, ciphertext, ciphertextLength) != 1) {
            openssl_error("EVP_DecryptUpdate failed");
        }
        totalLength = outLength;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) {
            openssl_error("EVP_CIPHER_CTX_ctrl (tag) failed");
        }
        finalResultLength = EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLength, &outLength);
    }
    catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);

    if (finalResultLength != 1) {
        throw std::runtime_error("Decrypt failed: wrong password or corrupted data");
    }

    totalLength += outLength;
    plaintext.resize(totalLength);

    return std::string(plaintext.begin(), plaintext.end());
}

struct Image {
    int width = 0, height = 0, channels = 0;
    std::vector<uint8_t> pixels;
};

Image loadImage(const std::string& path) {
    Image image;
    int width = 0, height = 0, channels = 0;

    uint8_t* data = stbi_load(path.c_str(), &width, &height, &channels, 3);
    if (!data) {
        throw std::runtime_error("Failed to load image");
    }
    image.width = width;
    image.height = height;
    image.channels = 3;
    image.pixels.assign(data, data + (size_t)width * height * channels);

    stbi_image_free(data);
    return image;
}

void savePNG(const std::string& path, const Image& image) {
    int ok = stbi_write_png(path.c_str(), image.width, image.height, image.channels, image.pixels.data(), image.width * image.channels);
    if (!ok) {
        throw std::runtime_error("Failed to save image");
    }
}

inline void setLSB(uint8_t& byte, int bit) {
    byte = (byte & 0xFE) | (bit & 0x01);
}

inline int getLSB(uint8_t byte) {
    return byte & 0x01;
}

void embedPayload(Image& image, const std::vector<uint8_t>& payload) {

    uint64_t totalBits = 32ULL + (uint64_t)payload.size() * 8ULL;
    if (totalBits > image.pixels.size()) {
        throw std::runtime_error("Payload too large for this image");
    }

    size_t bitIndex = 0;
    uint32_t length = (uint32_t)payload.size();

    for (int i = 31; i >= 0; --i) {
        setLSB(image.pixels[bitIndex++], (length >> i) & 1);
    }

    for (uint8_t byte : payload) {
        for (int i = 7; i >= 0; --i) {
            setLSB(image.pixels[bitIndex++], (byte >> i) & 1);
        }
    }
}

std::vector<uint8_t> extractPayload(Image& image) {
    size_t bitIndex = 0;
    uint32_t length = 0;

    for (int i = 0; i < 32; ++i) {
        length = (length << 1) | getLSB(image.pixels[bitIndex++]);
    }

    if ((uint64_t)length * 8ULL + 32ULL > image.pixels.size()) {
        throw std::runtime_error("No valid payload found");
    }

    std::vector<uint8_t> payload(length);

    for (uint32_t b = 0; b < length; ++b) {
        uint8_t byte = 0;
        for (int i = 0; i < 8; ++i) {
            byte = (byte << 1) | getLSB(image.pixels[bitIndex++]);
        }
        payload[b] = byte;
    }

    return payload;
}

int main() {

    std::string inFilePath = "../res/debug_image.png";
    std::string outFilePath = "../res/debug_image_with_payload.png";
    std::string password = "password123";
    std::string message = "hello world";

    Image inImage = loadImage(inFilePath);
    std::vector<uint8_t> inPayload = encrypt(message, password);
    embedPayload(inImage, inPayload);
    savePNG(outFilePath, inImage);

    Image outImage = loadImage(outFilePath);
    std::vector<uint8_t> outPayload = extractPayload(outImage);
    std::string msg = decrypt(outPayload, password);

    std::cout << msg << std::endl;
}