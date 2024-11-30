#ifndef FILE_HASH_LIBTOMCRYPT_H
#define FILE_HASH_LIBTOMCRYPT_H
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <tomcrypt.h>

//最多读取64kb大小的文件
#define BUFFER_SIZE 64*1024  


//md5-file
void md5_file(const std::string& filename);


//sha1-file
void sha1_file(const std::string& filename);


//sha256-file
void sha256_file(const std::string& filename);


//sha512-file
void sha512_file(const std::string& filename);

#endif 