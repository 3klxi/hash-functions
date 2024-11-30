//2222119 曹凯伦 信息安全2201班 2024.11.29
#ifndef FILE_HASH_SELF_H
#define FILE_HASH_SELF_H
#include "MD5.h"
#include "SHA-1.h"
#include "SHA-256.h"
#include "SHA-512.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>
#include <string>

//最多读取64kb大小的文件
#define BUFFER_SIZE 64*1024  

// my own MD5文件哈希
std::string self_md5_file(const std::string& filename);


// my own SHA-1文件哈希
std::string self_sha1_file(const std::string& filename);


// my own SHA-256 hash文件哈希
std::string self_sha256_file(const std::string& filename);


// my own SHA-512 hash文件哈希
std::string self_sha512_file(const std::string& filename);

#endif