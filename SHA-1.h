//2222119 曹凯伦 信息安全2201班 2024.11.24
#ifndef SHA_1_H
#define SHA_1_H
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstdint>

// 循环移位
uint32_t rotate_left(uint32_t value, uint32_t bits);

// sha1消息填充
std::vector<uint8_t> sha1_pad(const std::string& message);

// sha1压缩函数
void sha1_process_chunk(const uint8_t* chunk, uint32_t* H);

// SHA-1函数
std::string sha1(const std::string& message);

#endif
