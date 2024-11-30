#include "File_hash_LibTomCrypt.h"

//md5-file
void md5_file(const std::string& filename) {
    // 定义变量
    hash_state md;
    unsigned char md5_hash[16];  // MD5哈希值的长度是16个字节 128bits
    unsigned long md5_hash_len = 16;
    int err;

    // 打开文件
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: unable to open file " << filename << std::endl;
        return;
    }

    // 初始化 MD5 哈希状态
    if ((err = md5_init(&md)) != CRYPT_OK) {
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 读取文件并计算哈希值
    std::vector<unsigned char> buffer(BUFFER_SIZE);  // 文件读取缓冲区
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize read = file.gcount();  // 获取实际读取的字节数
        if (read > 0) {
            if ((err = md5_process(&md, buffer.data(), read)) != CRYPT_OK) {
                std::cerr << "Error: " << error_to_string(err) << std::endl;
                return;
            }
        }
    }

    // 计算最终的哈希值
    if ((err = md5_done(&md, md5_hash)) != CRYPT_OK) {
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 打印 MD5 哈希值
    std::cout << std::left <<std::setw(10)<< "MD5: ";
    for (unsigned long i = 0; i < md5_hash_len; i++) {
        std::cout << std::hex << (int)md5_hash[i];
    }
    std::cout << std::endl;
}


//sha1-file
void sha1_file(const std::string& filename) {
    // 定义变量
    hash_state sha1;
    unsigned char sha1_hash[20];  // SHA1摘要值长20字节
    unsigned long sha1_hash_len = 20;
    int err;

    // 打开文件
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: unable to open file " << filename << std::endl;
        return;
    }

    // 初始化 sha1 哈希状态
    if ((err = sha1_init(&sha1)) != CRYPT_OK) {
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 读取文件并计算哈希值
    std::vector<unsigned char> buffer(BUFFER_SIZE);  // 文件读取缓冲区
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize read = file.gcount();  // 获取实际读取的字节数
        if (read > 0) {
            if ((err = sha1_process(&sha1, buffer.data(), read)) != CRYPT_OK) {
                std::cerr << "Error: " << error_to_string(err) << std::endl;
                return;
            }
        }
    }

    // 计算最终的哈希值
    if ((err = sha1_done(&sha1, sha1_hash)) != CRYPT_OK) {
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 打印 Sha1 哈希值
    std::cout << std::left <<std::setw(10)<< "Sha1: ";
    for (unsigned long i = 0; i < sha1_hash_len; i++) {
        std::cout << std::hex << (int)sha1_hash[i];
    }
    std::cout << std::endl;
}


//sha256-file
void sha256_file(const std::string& filename) {
    // 定义变量
    hash_state sha256;
    unsigned char sha256_hash[32];  // SHA256摘要值长32字节
    unsigned long sha256_hash_len = 32;
    int err;

    // 打开文件
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: unable to open file " << filename << std::endl;
        return;
    }

    // 初始化 sha256 哈希状态
    if ((err = sha256_init(&sha256)) != CRYPT_OK) {
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 读取文件并计算哈希值
    std::vector<unsigned char> buffer(BUFFER_SIZE);  // 文件读取缓冲区
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize read = file.gcount();  // 获取实际读取的字节数
        if (read > 0) {
            if ((err = sha256_process(&sha256, buffer.data(), read)) != CRYPT_OK) {
                std::cerr << "Error: " << error_to_string(err) << std::endl;
                return;
            }
        }
    }

    // 计算最终的哈希值
    if ((err = sha256_done(&sha256, sha256_hash)) != CRYPT_OK) {
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 打印 Sha1 哈希值
    std::cout << std::left << std::setw(10) << "Sha256: ";
    for (unsigned long i = 0; i < sha256_hash_len; i++) {
        std::cout << std::hex << (int)sha256_hash[i];
    }
    std::cout << std::endl;
}


//sha512-file
void sha512_file(const std::string& filename) {
    // 定义变量
    hash_state sha512;
    unsigned char sha512_hash[64];  // SHA512摘要值长64字节
    unsigned long sha512_hash_len = 64;
    int err;

    // 打开文件
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: unable to open file " << filename << std::endl;
        return;
    }

    // 初始化 sha512 哈希状态
    if ((err = sha512_init(&sha512)) != CRYPT_OK) {  // 使用 sha512_init，而不是 sha256_init
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 读取文件并计算哈希值
    std::vector<unsigned char> buffer(BUFFER_SIZE);  // 文件读取缓冲区
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize read = file.gcount();  // 获取实际读取的字节数
        if (read > 0) {
            if ((err = sha512_process(&sha512, buffer.data(), read)) != CRYPT_OK) {  // 使用 sha512_process，而不是 sha256_process
                std::cerr << "Error: " << error_to_string(err) << std::endl;
                return;
            }
        }
    }

    // 计算最终的哈希值
    if ((err = sha512_done(&sha512, sha512_hash)) != CRYPT_OK) {  // 使用 sha512_done，而不是 sha256_done
        std::cerr << "Error: " << error_to_string(err) << std::endl;
        return;
    }

    // 打印 Sha512 哈希值
    std::cout << std::left << std::setw(10) << "Sha512: ";
    for (unsigned long i = 0; i < sha512_hash_len; i++) {
        std::cout <<  std::setfill('0') << (int)sha512_hash[i];
    }
    std::cout << std::endl;
}