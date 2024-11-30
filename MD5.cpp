#include "MD5.h"

// 循环左移
uint32_t md5_rotate_left(uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (32 - shift));
}


// 消息填充
std::vector<uint8_t> md5_pad(const std::string& message) {
    std::vector<uint8_t> padded(message.begin(), message.end());
    uint64_t bit_len = message.size() * 8;

    // 先填充 '1' bit   (1000 0000)  (0x80) 
    padded.push_back(0x80);

    // 添加 '0' bit，直到 bits=448 size=56
    while ((padded.size() % 64) != 56) {
        padded.push_back(0x00);
    }

    // 追加消息的长度 mod 2^64
    for (int i = 0; i < 8; ++i) {
        padded.push_back(static_cast<uint8_t>(bit_len >> (i * 8)));
    }

    return padded;
}


// 步函数、压缩函数 512bits->128bits
void md5_process_chunk(const uint8_t* chunk, uint32_t* H) {   //chunk字节数组-512bits-64字节
    
    // 消息子分组Mi，i-[0,15]，大端
    uint32_t M[16];       
    for (int i = 0; i < 16; ++i) {   
        M[i] = (chunk[i * 4]) | (chunk[i * 4 + 1] << 8) |
            (chunk[i * 4 + 2] << 16) | (chunk[i * 4 + 3] << 24);  // chunk=[0x01, 0x02, 0x03, 0x04,...] ---> M1=0x04 0x03 0x02 0x01
    }    

    // 初始化4个32bits寄存器
    uint32_t A = H[0], B = H[1], C = H[2], D = H[3];

    // 循环 4轮 64步
    for (int i = 0; i < 64; ++i) {
        //不同的非线性函数输出的结果F
        uint32_t F, g;
        if (i < 16) {
            F = (B & C) | (~B & D);
            g = i;
        }
        else if (i < 32) {
            F = (D & B) | (~D & C);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48) {
            F = B ^ C ^ D;
            g = (3 * i + 5) % 16;
        }
        else {
            F = C ^ (B | ~D);
            g = (7 * i) % 16;
        }
        uint32_t temp = D;
        D = C;
        C = B;
        B = B + md5_rotate_left(A + F + T[i] + M[g], S[i]);
        A = temp;
    }

    // 最终的ABCD与最初输入的链接变量进行模加
    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
}

// MD5函数
std::string md5_hash(const std::string& message) {
    // 初始化链接变量
    uint32_t H[4] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    };

    // 填充消息
    std::vector<uint8_t> padded = md5_pad(message);

    // 处理512bits的分组
    for (size_t i = 0; i < padded.size(); i += 64) {
        md5_process_chunk(&padded[i], H);
    }

    // 组合最终的hash值
    std::ostringstream result;   //字符串流对象，格式化字符串，拼接成最终的hash digest
    for (int i = 0; i < 4; ++i) {
        result << std::hex << std::setw(8) << std::setfill('0')     //8个十六进制的字符
            << ((H[i] & 0xFF) << 24 | (H[i] & 0xFF00) << 8 |
                (H[i] & 0xFF0000) >> 8 | (H[i] >> 24));         //[H1, H2, H3, H4]  
                
                //H[i] & 0xFF)最低字节  H[i]最高字节   用于将大小端转换
    }

    return result.str();
}

