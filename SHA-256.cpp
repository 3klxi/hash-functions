#include "SHA-256.h"

// 消息填充
std::vector<uint8_t> sha256_pad(const std::string& message) {
    std::vector<uint8_t> padded(message.begin(), message.end());
    uint64_t bit_len = message.size() * 8;

    // 追加bit 1
    padded.push_back(0x80);

    // 追加bit 0 直至448bits
    while ((padded.size() % 64) != 56) {
        padded.push_back(0x00);
    }

    // 追加消息的长度 mod2^64
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>(bit_len >> (i * 8)));
    }

    return padded;
}

// sha256压缩函数
void sha256_process_chunk(const uint8_t* chunk, uint32_t* H) {
    uint32_t W[64];   //64个消息字
    for (int i = 0; i < 16; ++i) {
        W[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16) |
            (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
    }//默认导出16*32bits 16个字

    //导出16-59的48个字
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR(W[i - 15], 7) ^ ROTR(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = ROTR(W[i - 2], 17) ^ ROTR(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    //初始化的8个32bits寄存器
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];


    //64轮（步）
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    //最终的模加
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}


// SHA-256 函数
std::string sha256(const std::string& message) {
    //初始化8个寄存器
    uint32_t H[] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    //消息填充
    std::vector<uint8_t> padded = sha256_pad(message);
    for (size_t i = 0; i < padded.size(); i += 64) {
        sha256_process_chunk(&padded[i], H);          //压缩
    }


    //组合最终的hash
    std::ostringstream result;
    for (int i = 0; i < 8; ++i) {
        result << std::hex << std::setw(8) << std::setfill('0') << H[i];
    }
    return result.str();
}