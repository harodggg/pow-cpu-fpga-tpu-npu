#include <iostream>
#include <cuda_runtime.h>
#include <cstdint>

// ==========================================
// 1. 标准 SHA-256 基础运算逻辑 (GPU 设备端)
// ==========================================
__device__ inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__device__ inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

__device__ inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

__device__ inline uint32_t s0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ inline uint32_t s1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// 64 轮常数表 K
__device__ __constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __constant__ uint32_t c_header[19] = {
    0x01000000, 
    0x6fe28c0a, 0xb6f1b372, 0xc1a6a246, 0xae63f74f, 
    0x931e8365, 0xe15a089c, 0x68d61900, 0x00000000, 
    0xf481bad8, 0x9c6b7d0b, 0xb05d20e7, 0xb08a2b76, 
    0x897e34a3, 0xa6efeea4, 0xe269298b, 0x222e9c6f, 
    0x81ad5f49, 
    0xffffff1c  
};

// 标准单块 64 轮压缩核心
__device__ void sha256_transform(uint32_t state[8], const uint32_t data[16]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++) W[i] = data[i];
    for (int i = 16; i < 64; i++) {
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// 完整的 80 字节哈希计算（两口吞完）
__device__ uint32_t hash_header(uint32_t nonce) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // 第一口：前 64 字节（c_header 的前 16 个字）
    uint32_t chunk1[16];
    for (int i = 0; i < 16; i++) {
        chunk1[i] = c_header[i];
    }
    sha256_transform(state, chunk1);

    // 第二口：后 16 字节（c_header 剩下的 3 个字 + 你的 nonce）+ 补齐
    uint32_t chunk2[16];
    chunk2[0] = c_header[16];
    chunk2[1] = c_header[17];
    chunk2[2] = c_header[18];
    chunk2[3] = nonce;       // <-- 拼上当前线程负责的 Nonce！
    chunk2[4] = 0x80000000;  // 补 1 和 0
    for (int i = 5; i < 15; i++) {
        chunk2[i] = 0x00000000;
    }
    chunk2[15] = 640;        // 80 字节 = 640 位

    sha256_transform(state, chunk2);

    return state[0]; // 返回哈希结果的最高位 32 bit 验证
}



__global__ void miner_kernel(uint32_t base_nonce, uint32_t target_mask, uint32_t *result, uint32_t *found) {
    if (*found == 1) return;

    uint32_t thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t nonce = base_nonce + thread_id;

    uint32_t h0 = hash_header(nonce);

    if (h0 < target_mask) {
        if (atomicCAS(found, 0, 1) == 0) {
            *result = nonce;
        }
    }
}


int main() {
    std::cout << "开始GPU计算......" << std::endl;

    // 1. 创建cpu 和 gpu 共享显存。
    uint32_t *result = nullptr;
    uint32_t *found = nullptr;

    cudaMallocManaged(&result, sizeof(uint32_t));
    cudaMallocManaged(&found, sizeof(uint32_t));

    *result = 0;
    *found = 0;

    
    uint32_t target_mask = 0x1a00FFFF;
    uint32_t base_nonce = 0;

    miner_kernel<<<65536, 256>>>(base_nonce, target_mask, result, found);
    cudaDeviceSynchronize();

    // 5. 在 CPU 端直接读取
    if (*found == 1) {
        std::cout << "成功找到 Nonce: " << *result << std::endl;
    } else {
        std::cout << "本批次未找到符合条件的 Nonce。" << std::endl;
    }

    // 释放显存
    cudaFree(result);
    cudaFree(found);

    return 0;
}