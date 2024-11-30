#include "File_hash_self.h"

// my own MD5文件哈希
std::string self_md5_file(const std::string& filename) {
    // Open
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: unable to open file " << filename << std::endl;
        return "";
    }

    // Read
    std::ostringstream oss;
    oss << file.rdbuf();
    std::string file_content = oss.str();

    // MD5 hash
    return md5_hash(file_content);
}


// my own SHA-1文件哈希
std::string self_sha1_file(const std::string& filename) {
    // Open
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Could not open the file!" << std::endl;
        return "";
    }

    // Read
    std::ostringstream contentStream;
    contentStream << file.rdbuf();
    std::string content = contentStream.str();
    
    // SHA-1 hash
    return sha1(content);
}


// SHA-256 hash文件哈希
std::string self_sha256_file(const std::string& filename) {
    // Open
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Could not open the file!" << std::endl;
        return "";
    }

    // Read
    std::ostringstream contentStream;
    contentStream << file.rdbuf();
    std::string content = contentStream.str();
    
    // SHA-256 hash
    return sha256(content);
}


// SHA-512 hash文件哈希
std::string self_sha512_file(const std::string& filename) {
    // Open
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Could not open the file!" << std::endl;
        return "";
    }

    // Read
    std::ostringstream contentStream;
    contentStream << file.rdbuf();
    std::string content = contentStream.str();
    
    // SHA-512 hash
    return sha512(content);
}