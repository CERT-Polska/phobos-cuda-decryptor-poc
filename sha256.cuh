// MIT License

// Copyright (c) 2023 Moffa Jérémy

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#ifndef SHA256_H
#define SHA256_H

#define checkCudaErrors(x) \
{ \
    cudaGetLastError(); \
    x; \
    cudaError_t err = cudaGetLastError(); \
    if (err != cudaSuccess) \
        printf("GPU: cudaError %d (%s)\n", err, cudaGetErrorString(err)); \
}

__device__ constexpr uint32_t dev_k(int i) {
    constexpr uint32_t dev_k_raw[] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    return dev_k_raw[i];
};

__device__ const uint32_t sha256_h[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__device__ void mycpy16(uint32_t *d, const uint32_t *s) {
    int4 *dv = (int4*)d;
    int4 *sv = (int4*)s;
    dv[0] = sv[0];
}

__device__ void mycpy32(uint32_t *d, const uint32_t *s) {
    int4 *dv = (int4*)d;
    int4 *sv = (int4*)s;
    dv[0] = sv[0];
    dv[1] = sv[1];
}

__device__ void mycpy64(uint32_t *d, const uint32_t *s) {
    int4 *dv = (int4*)d;
    int4 *sv = (int4*)s;
    dv[0] = sv[0];
    dv[1] = sv[1];
    dv[2] = sv[2];
    dv[3] = sv[3];
}

#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define ROTR(x, n)      ((x >> n) | (x << (32 - n)))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))


#define RND(a, b, c, d, e, f, g, h, k) \
    do { \
        uint32_t t0 = h + S1(e) + Ch(e, f, g) + k; \
        uint32_t t1 = S0(a) + Maj(a, b, c); \
        d += t0; \
        h  = t0 + t1; \
    } while (0)

#define RNDr(S, W, i) \
    RND(S[(64 - i) % 8], S[(65 - i) % 8], \
        S[(66 - i) % 8], S[(67 - i) % 8], \
        S[(68 - i) % 8], S[(69 - i) % 8], \
        S[(70 - i) % 8], S[(71 - i) % 8], \
        W[i] + dev_k(i))

__device__ void sha256_transform(uint32_t block[])
{
    uint32_t W[64]; // only 4 of these are accessed during each partial Mix
    uint32_t S[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    constexpr uint32_t WH[] = {
        0, 0, 0, 0,  // dummy
        0, 0, 0, 0,  // dummy
        0x80000000, 0, 0, 0,
        0, 0, 0, 0x100
    };

    /* 2. Prepare message schedule W and Mix. */
    mycpy16(W, (const uint32_t*)(block+0));
    RNDr(S, W,  0);
    RNDr(S, W,  1);
    RNDr(S, W,  2);
    RNDr(S, W,  3);

    mycpy16(W+4, (const uint32_t*)(block+4));
    RNDr(S, W,  4);
    RNDr(S, W,  5);
    RNDr(S, W,  6);
    RNDr(S, W,  7);

    RNDr(S, WH,  8);
    RNDr(S, WH,  9);
    RNDr(S, WH, 10);
    RNDr(S, WH, 11);

    RNDr(S, WH, 12);
    RNDr(S, WH, 13);
    RNDr(S, WH, 14);
    RNDr(S, WH, 15);

    W[16] = s1(WH[14]) + WH[9] + s0(W[1]) + W[0];
    RNDr(S, W, 16);
    W[17] = s1(WH[15]) + WH[10] + s0(W[2]) + W[1];
    RNDr(S, W, 17);
    W[18] = s1(W[16]) + WH[11] + s0(W[3]) + W[2];
    RNDr(S, W, 18);
    W[19] = s1(W[17]) + WH[12] + s0(W[4]) + W[3];
    RNDr(S, W, 19);
    W[20] = s1(W[18]) + WH[13] + s0(W[5]) + W[4];
    RNDr(S, W, 20);
    W[21] = s1(W[19]) + WH[14] + s0(W[6]) + W[5];
    RNDr(S, W, 21);
    W[22] = s1(W[20]) + WH[15] + s0(W[7]) + W[6];
    RNDr(S, W, 22);
    W[23] = s1(W[21]) + W[16] + s0(WH[8]) + W[7];
    RNDr(S, W, 23);
    W[24] = s1(W[22]) + W[17] + s0(WH[9]) + WH[8];
    RNDr(S, W, 24);
    W[25] = s1(W[23]) + W[18] + s0(WH[10]) + WH[9];
    RNDr(S, W, 25);
    W[26] = s1(W[24]) + W[19] + s0(WH[11]) + WH[10];
    RNDr(S, W, 26);
    W[27] = s1(W[25]) + W[20] + s0(WH[12]) + WH[11];
    RNDr(S, W, 27);
    W[28] = s1(W[26]) + W[21] + s0(WH[13]) + WH[12];
    RNDr(S, W, 28);
    W[29] = s1(W[27]) + W[22] + s0(WH[14]) + WH[13];
    RNDr(S, W, 29);
    W[30] = s1(W[28]) + W[23] + s0(WH[15]) + WH[14];
    RNDr(S, W, 30);
    W[31] = s1(W[29]) + W[24] + s0(W[16]) + WH[15];
    RNDr(S, W, 31);
    W[32] = s1(W[30]) + W[25] + s0(W[17]) + W[16];
    RNDr(S, W, 32);
    W[33] = s1(W[31]) + W[26] + s0(W[18]) + W[17];
    RNDr(S, W, 33);
    W[34] = s1(W[32]) + W[27] + s0(W[19]) + W[18];
    RNDr(S, W, 34);
    W[35] = s1(W[33]) + W[28] + s0(W[20]) + W[19];
    RNDr(S, W, 35);
    W[36] = s1(W[34]) + W[29] + s0(W[21]) + W[20];
    RNDr(S, W, 36);
    W[37] = s1(W[35]) + W[30] + s0(W[22]) + W[21];
    RNDr(S, W, 37);
    W[38] = s1(W[36]) + W[31] + s0(W[23]) + W[22];
    RNDr(S, W, 38);
    W[39] = s1(W[37]) + W[32] + s0(W[24]) + W[23];
    RNDr(S, W, 39);
    W[40] = s1(W[38]) + W[33] + s0(W[25]) + W[24];
    RNDr(S, W, 40);
    W[41] = s1(W[39]) + W[34] + s0(W[26]) + W[25];
    RNDr(S, W, 41);
    W[42] = s1(W[40]) + W[35] + s0(W[27]) + W[26];
    RNDr(S, W, 42);
    W[43] = s1(W[41]) + W[36] + s0(W[28]) + W[27];
    RNDr(S, W, 43);
    W[44] = s1(W[42]) + W[37] + s0(W[29]) + W[28];
    RNDr(S, W, 44);
    W[45] = s1(W[43]) + W[38] + s0(W[30]) + W[29];
    RNDr(S, W, 45);
    W[46] = s1(W[44]) + W[39] + s0(W[31]) + W[30];
    RNDr(S, W, 46);
    W[47] = s1(W[45]) + W[40] + s0(W[32]) + W[31];
    RNDr(S, W, 47);
    W[48] = s1(W[46]) + W[41] + s0(W[33]) + W[32];
    RNDr(S, W, 48);
    W[49] = s1(W[47]) + W[42] + s0(W[34]) + W[33];
    RNDr(S, W, 49);
    W[50] = s1(W[48]) + W[43] + s0(W[35]) + W[34];
    RNDr(S, W, 50);
    W[51] = s1(W[49]) + W[44] + s0(W[36]) + W[35];
    RNDr(S, W, 51);
    W[52] = s1(W[50]) + W[45] + s0(W[37]) + W[36];
    RNDr(S, W, 52);
    W[53] = s1(W[51]) + W[46] + s0(W[38]) + W[37];
    RNDr(S, W, 53);
    W[54] = s1(W[52]) + W[47] + s0(W[39]) + W[38];
    RNDr(S, W, 54);
    W[55] = s1(W[53]) + W[48] + s0(W[40]) + W[39];
    RNDr(S, W, 55);
    W[56] = s1(W[54]) + W[49] + s0(W[41]) + W[40];
    RNDr(S, W, 56);
    W[57] = s1(W[55]) + W[50] + s0(W[42]) + W[41];
    RNDr(S, W, 57);
    W[58] = s1(W[56]) + W[51] + s0(W[43]) + W[42];
    RNDr(S, W, 58);
    W[59] = s1(W[57]) + W[52] + s0(W[44]) + W[43];
    RNDr(S, W, 59);
    W[60] = s1(W[58]) + W[53] + s0(W[45]) + W[44];
    RNDr(S, W, 60);
    W[61] = s1(W[59]) + W[54] + s0(W[46]) + W[45];
    RNDr(S, W, 61);
    W[62] = s1(W[60]) + W[55] + s0(W[47]) + W[46];
    RNDr(S, W, 62);
    W[63] = s1(W[61]) + W[56] + s0(W[48]) + W[47];
    RNDr(S, W, 63);
    
    /* 3. Mix local working variables into global state */
#pragma unroll 8
    for (int i = 0; i < 8; i++)
    block[i] = sha256_h[i] + S[i];
}

#endif   // SHA256_H
