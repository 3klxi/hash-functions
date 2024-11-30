#include "SHA-512.h"

// sha512填充
std::vector<uint8_t> sha512_pad(const std::string& message) {
    std::vector<uint8_t> padded(message.begin(), message.end());
    uint64_t bit_len = message.size() * 8;

    // 追加bit 1
    padded.push_back(0x80);

    // 追加bit 0，直至896
    while ((padded.size() % 128) != 112) {
        padded.push_back(0x00);
    }

    // 添加消息的长度
    for (int i = 15; i >= 8; --i) {
        padded.push_back(0x00); // 高64bits对于标准的SHA512算法，不使用
    }
    //低64bits，用来填充消息的长度mod 2^128，用不上如此大，所以mod 2^64即可
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>(bit_len >> (i * 8)));
    }

    return padded;
}

// sha512压缩函数
void sha512_process_chunk(const uint8_t* chunk, uint64_t* H) {
    uint64_t W[80] = { 0 };  //80轮的消息字

    // 默认导出前16*64bits 1024 bits
    for (int i = 0; i < 16; ++i) {
        W[i] = (static_cast<uint64_t>(chunk[i * 8]) << 56) |
            (static_cast<uint64_t>(chunk[i * 8 + 1]) << 48) |
            (static_cast<uint64_t>(chunk[i * 8 + 2]) << 40) |
            (static_cast<uint64_t>(chunk[i * 8 + 3]) << 32) |
            (static_cast<uint64_t>(chunk[i * 8 + 4]) << 24) |
            (static_cast<uint64_t>(chunk[i * 8 + 5]) << 16) |
            (static_cast<uint64_t>(chunk[i * 8 + 6]) << 8) |
            (static_cast<uint64_t>(chunk[i * 8 + 7]));
    }

    // 扩展剩下的64*64bits 消息子分组
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = ROTR64(W[i - 15], 1) ^ ROTR64(W[i - 15], 8) ^ (W[i - 15] >> 7);
        uint64_t s1 = ROTR64(W[i - 2], 19) ^ ROTR64(W[i - 2], 61) ^ (W[i - 2] >> 6);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    // 初始化链接链接变量,到8个64bits寄存器中， 8*64bits  512bits
    uint64_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint64_t e = H[4], f = H[5], g = H[6], h = H[7];

    // 80轮 函数
    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t temp1 = h + S1 + ch + K512[i] + W[i];
        uint64_t S0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // 模加
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}



// SHA-512 函数
std::string sha512(const std::string& message) {
    // 初始化8个64bits寄存器（链接变量）
    uint64_t H[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    // 消息填充
    std::vector<uint8_t> padded = sha512_pad(message);

    // sha512压缩 1024bits ---> 512bits
    for (size_t i = 0; i < padded.size(); i += 128) {
        sha512_process_chunk(&padded[i], H);
    }

    // 组合最终的hash值
    std::ostringstream result;
    for (int i = 0; i < 8; ++i) {
        result << std::hex << std::setw(16) << std::setfill('0') << H[i];
    }

    return result.str();
}