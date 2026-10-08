#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>

#include <stdint.h>
#include <time.h>

using namespace std;

/* Debug counters used to track filter efficiency in AES_192_7round */
uint64_t DEBUG_N = 0;      /* number of candidates passing the innermost check */
uint64_t DEBUG_M = 0;      /* number of candidates reaching the innermost check */

/* AES S-box: non-linear substitution table used in SubBytes */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Inverse AES S-box: used in InvSubBytes */
static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static uint8_t LookupTable[256][256][256] = {0}; /* Precomputed lookup table for the innermost check */
static uint8_t LookupTableExist[256][256][256] = {0}; /* Precomputed lookup table for the innermost check */

/* GF(2^8) multiplication by 2 with polynomial reduction by 0x1b */
// #define mul2(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b) & 0xFF)

#define mul2(x) ((((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b)) & 0xFF)

/* GF(2^8) multiplication by 3: x*3 = x*2 XOR x */
#define mul3(x) (mul2(x) ^ (x))

/* DEVICE_FUNC: resolves to __device__ under NVCC, inline under OpenCL, static inline on CPU */
#ifdef __NVCC__
    // CUDA version
    #define DEVICE_FUNC __device__ __forceinline__
#elif defined(__OPENCL__)
    // OpenCL version
    #define DEVICE_FUNC inline
#else
    // CPU version
    #define DEVICE_FUNC static inline
#endif

/* xorshift64star - Fast 64-bit PRNG; each thread seeds it from its global thread index */
DEVICE_FUNC uint64_t xorshift64star(uint64_t x) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1DULL;
}

/* GF(2^8) constant multiplications used in MixColumns and its inverse. */
DEVICE_FUNC uint8_t mul4(uint8_t x){
    uint8_t out = mul2(mul2(x));
    return out;
}

DEVICE_FUNC uint8_t mul7(uint8_t x){
    uint8_t out = mul4(x) ^ mul2(x) ^ x;
    return out;
}

DEVICE_FUNC uint8_t mul8(uint8_t x){
    uint8_t out = mul4(mul2(x));
    return out;
}

DEVICE_FUNC uint8_t mul10(uint8_t x){
    uint8_t out = mul8(mul2(x));
    return out;
}

DEVICE_FUNC uint8_t mul20(uint8_t x){
    uint8_t out = mul10(mul2(x));
    return out;
}

DEVICE_FUNC uint8_t mul40(uint8_t x){
    uint8_t out = mul20(mul2(x));
    return out;
}

DEVICE_FUNC uint8_t mul80(uint8_t x){
    uint8_t out = mul40(mul2(x));
    return out;
}

DEVICE_FUNC uint8_t mul8c(uint8_t x){
    uint8_t out = mul80(x) ^ mul8(x) ^ mul4(x);
    return out;
}

DEVICE_FUNC uint8_t mul8d(uint8_t x){
    uint8_t out = mul80(x) ^ mul8(x) ^ mul4(x) ^ x;
    return out;
}

DEVICE_FUNC uint8_t mulf6(uint8_t x){
    uint8_t out = mul80(x) ^ mul40(x) ^ mul20(x) ^ mul10(x) ^ mul4(x) ^ mul2(x);
    return out;
}

DEVICE_FUNC uint8_t mulf7(uint8_t x){
    uint8_t out = mul80(x) ^ mul40(x) ^ mul20(x) ^ mul10(x) ^ mul4(x) ^ mul2(x) ^ x;
    return out;
}

DEVICE_FUNC uint8_t mulb8(uint8_t x){
    uint8_t out = mul80(x) ^ mul20(x) ^ mul10(x) ^ mul8(x);
    return out;
}

DEVICE_FUNC uint8_t mulb9(uint8_t x){
    uint8_t out = mul80(x) ^ mul20(x) ^ mul10(x) ^ mul8(x) ^ x;
    return out;
}

DEVICE_FUNC uint8_t muld1(uint8_t x){
    uint8_t out = mul80(x) ^ mul40(x) ^ mul10(x) ^ x;
    return out;
}

DEVICE_FUNC bool allowed34to7b(uint8_t x){
    return x == 0x00 || x == 0x34 || x == 0x99 || x == 0xAD;
}

DEVICE_FUNC bool allowedDato34(uint8_t x){
    return x == 0x00 || x == 0x7C || x == 0xA6 || x == 0xDA;
}

bool AES_256_12r(uint8_t* plaintext, const uint8_t* key, bool checkCondition){
    uint8_t keyBlock[7][32];
    uint8_t state[4][4];
    uint8_t tstate[4];

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            keyBlock[0][8 * i + j] = key[4 * i + j];
            keyBlock[0][8 * i + 4 + j] = key[16 + 4 * i + j];
        }
    }

    for (int i = 1; i < 7; i++){
        keyBlock[i][0] = sbox[keyBlock[i - 1][15]] ^ (1 << (i - 1)) ^ keyBlock[i - 1][0];
        keyBlock[i][8] = sbox[keyBlock[i - 1][23]] ^ keyBlock[i - 1][8];
        keyBlock[i][16] = sbox[keyBlock[i - 1][31]] ^ keyBlock[i - 1][16];
        keyBlock[i][24] = sbox[keyBlock[i - 1][7]] ^ keyBlock[i - 1][24];
        for (int j = 1; j < 32; j++){
            if (j % 8 != 0){
                if (j % 8 == 4){
                    keyBlock[i][j] = keyBlock[i - 1][j] ^ sbox[keyBlock[i][j - 1]];
                }
                else{
                    keyBlock[i][j] = keyBlock[i - 1][j] ^ keyBlock[i][j - 1];
                }
            }
        }
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = plaintext[4 * i + j];
        }
    }

    for (int r = 0; r < 12; r++){
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                int word = 4 * r + j;
                state[i][j] ^= keyBlock[word / 8][8 * i + word % 8];
            }
        }

        if (checkCondition){
            if (r == 5 && !allowed34to7b(state[0][0])){
                return false;
            }
            if (r == 6 && (!allowedDato34(state[0][0]) || !allowedDato34(state[0][1]) ||
                           !allowedDato34(state[0][2]) || !allowedDato34(state[0][3]))){
                return false;
            }
            // if (r == 8 && (!allowedDato34(state[0][0]) || !allowedDato34(state[0][2]))){
            //     return false;
            // }
            // if (r == 10 && (!allowedDato34(state[0][0]) || !allowedDato34(state[0][1]))){
            //     return false;
            // }
        }

        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                state[i][j] = sbox[state[i][j]];
            }
        }

        uint8_t temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;

        if (r != 11){
            for (int j = 0; j < 4; j++){
                tstate[0] = mul2(state[0][j]) ^ mul3(state[1][j]) ^ state[2][j] ^ state[3][j];
                tstate[1] = state[0][j] ^ mul2(state[1][j]) ^ mul3(state[2][j]) ^ state[3][j];
                tstate[2] = state[0][j] ^ state[1][j] ^ mul2(state[2][j]) ^ mul3(state[3][j]);
                tstate[3] = mul3(state[0][j]) ^ state[1][j] ^ state[2][j] ^ mul2(state[3][j]);
                state[0][j] = tstate[0];
                state[1][j] = tstate[1];
                state[2][j] = tstate[2];
                state[3][j] = tstate[3];
            }
        }
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            int word = 48 + j;
            state[i][j] ^= keyBlock[word / 8][8 * i + word % 8];
            plaintext[4 * i + j] = state[i][j];
        }
    }

    return true;
}

bool verify5rAES(uint8_t* plaintext, const uint8_t* key, uint8_t roundKey[][4][4], int round){
    // uint8_t roundKey[8][4][4];
    uint8_t keyBlock[4][32];
    uint8_t state[4][4];
    uint8_t tstate[4];
    for (int i = 0; i < 4; i ++){
        for (int j = 0; j < 4; j ++){
            keyBlock[0][8*i+j] = key[4*i+j];
            keyBlock[0][8*i+4+j] = key[16+4*i+j];
        }
    }
    for (int i = 1; i < 4; i ++){
        keyBlock[i][0] = sbox[keyBlock[i-1][15]] ^ (1 << (i-1)) ^ keyBlock[i-1][0];
        keyBlock[i][8] = sbox[keyBlock[i-1][23]] ^ keyBlock[i-1][8];
        keyBlock[i][16] = sbox[keyBlock[i-1][31]] ^ keyBlock[i-1][16];
        keyBlock[i][24] = sbox[keyBlock[i-1][7]] ^ keyBlock[i-1][24];
        for (int j = 1; j < 32; j++){
            if (j % 8 != 0){
                if (j % 8 == 4){
                    keyBlock[i][j] = keyBlock[i-1][j] ^ sbox[keyBlock[i][j-1]];
                }
                else{
                    keyBlock[i][j] = keyBlock[i-1][j] ^ keyBlock[i][j-1];
                }
            }
        }
    }
    for (int r = 0; r < 8; r ++){
        for (int i = 0; i < 4; i ++){
            for (int j = 0; j < 4; j ++){
                roundKey[r][i][j] = keyBlock[(4*r+j)/8][8*i+(4*r+j)%8];
            }
        }
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = plaintext[i * 4 + j];
        }
    }
    for (int r = 0; r < round; r ++){
        // AddRoundKey
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                state[i][j] ^= roundKey[r][i][j];
            }
        }
        // SubBytes
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                state[i][j] = sbox[state[i][j]];
            }
        }
        // ShiftRows
        uint8_t temp;
        // row 1: shift left by 1
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;
        // row 2: shift left by 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        // row 3: shift left by 3
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
        // MixColumns
        for (int j = 0; j < 4; j++){
            tstate[0] = mul2(state[0][j]) ^ mul3(state[1][j]) ^ state[2][j] ^ state[3][j];
            tstate[1] = state[0][j] ^ mul2(state[1][j]) ^ mul3(state[2][j]) ^ state[3][j];
            tstate[2] = state[0][j] ^ state[1][j] ^ mul2(state[2][j]) ^ mul3(state[3][j]);
            tstate[3] = mul3(state[0][j]) ^ state[1][j] ^ state[2][j] ^ mul2(state[3][j]);
            state[0][j] = tstate[0];
            state[1][j] = tstate[1];
            state[2][j] = tstate[2];
            state[3][j] = tstate[3];
        }
    }
    // final AddRoundKey with the last round key
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] ^= roundKey[round][i][j];
        }
    }
    // Write the ciphertext back into the plaintext buffer
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            plaintext[i * 4 + j] = state[i][j];
        }
    }
    return true;
}

void MakeTable(){
    int c2, c3, c5;
    int A, B, C, D, R, S;
    memset((void*)LookupTable, 0, sizeof(LookupTable));
    memset((void*)LookupTableExist, 0, sizeof(LookupTableExist));
    for(c2 = 0; c2 < 256; c2++){
        for(c3 = 0; c3 < 256; c3++){
            for(B = 0; B < 256; B++){
                C = rsbox[c2 ^ mul3(sbox[B])];
                S = c2 ^ c3 ^ sbox[B];
                R = mul2(c2) ^ mul7(sbox[B]);
                c5 = mul3(sbox[S]) ^ sbox[R];
                LookupTable[c2][c3][c5] = B;
                LookupTableExist[c2][c3][c5] = 1;
            }
        }
    }
}

bool GDprocess(const uint8_t* guessedBytes, uint8_t* plaintext, uint8_t* key){
    uint8_t k0[4][4], k1[4][4], k2[4][4], k3[4][4], k4[4][4], k5[4][4], k6[4][4], k7[4][4];
    uint8_t x0[4][4], x1[4][4], x2[4][4], x3[4][4], x4[4][4];
    uint8_t z0[4][4], z1[4][4], z2[4][4], z3[4][4], z4[4][4];
    uint8_t w0[4][4], w1[4][4], w2[4][4], w3[4][4];

    // set round 0
    x0[0][0] = 0x00; x0[0][1] = 0x66; x0[0][2] = 0x00; x0[0][3] = 0x00;
    x0[1][0] = 0x82; x0[1][1] = 0xAA; x0[1][2] = 0x19; x0[1][3] = 0x00;
    x0[2][0] = 0x31; x0[2][1] = 0x24; x0[2][2] = 0x34; x0[2][3] = 0x09;
    x0[3][0] = 0x0F; x0[3][1] = 0x43; x0[3][2] = 0x00; x0[3][3] = 0x26;

    // set round 1-4
    x1[0][0] = 0x63; x1[0][2] = 0xD2; x1[1][1] = 0x00; x1[2][2] = 0x01; x1[3][3] = 0xA1;
    x2[0][0] = 0xC2; x2[0][1] = 0x00;
    x3[0][0] = 0x00; x3[0][1] = 0x00;
    x4[0][0] = 0x00;

    // set key
    k6[0][3] = 0x00; k7[0][3] = 0xAC; k7[1][3] = 0x04; k7[2][3] = 0x00; k7[3][3] = 0x2D;

    // step1
    z0[0][0] = sbox[x0[0][0]]; z0[0][1] = sbox[x0[0][1]]; z0[0][2] = sbox[x0[0][2]]; z0[0][3] = sbox[x0[0][3]];
    z0[1][0] = sbox[x0[1][1]]; z0[1][1] = sbox[x0[1][2]]; z0[1][2] = sbox[x0[1][3]]; z0[1][3] = sbox[x0[1][0]];
    z0[2][0] = sbox[x0[2][2]]; z0[2][1] = sbox[x0[2][3]]; z0[2][2] = sbox[x0[2][0]]; z0[2][3] = sbox[x0[2][1]];
    z0[3][0] = sbox[x0[3][3]]; z0[3][1] = sbox[x0[3][0]]; z0[3][2] = sbox[x0[3][1]]; z0[3][3] = sbox[x0[3][2]];
    w0[0][0] = mul2(z0[0][0]) ^ mul3(z0[1][0]) ^ z0[2][0] ^ z0[3][0]; 
    w0[0][1] = mul2(z0[0][1]) ^ mul3(z0[1][1]) ^ z0[2][1] ^ z0[3][1]; 
    w0[0][2] = mul2(z0[0][2]) ^ mul3(z0[1][2]) ^ z0[2][2] ^ z0[3][2]; 
    w0[0][3] = mul2(z0[0][3]) ^ mul3(z0[1][3]) ^ z0[2][3] ^ z0[3][3];
    w0[1][0] = z0[0][0] ^ mul2(z0[1][0]) ^ mul3(z0[2][0]) ^ z0[3][0]; 
    w0[1][1] = z0[0][1] ^ mul2(z0[1][1]) ^ mul3(z0[2][1]) ^ z0[3][1]; 
    w0[1][2] = z0[0][2] ^ mul2(z0[1][2]) ^ mul3(z0[2][2]) ^ z0[3][2]; 
    w0[1][3] = z0[0][3] ^ mul2(z0[1][3]) ^ mul3(z0[2][3]) ^ z0[3][3];
    w0[2][0] = z0[0][0] ^ z0[1][0] ^ mul2(z0[2][0]) ^ mul3(z0[3][0]); 
    w0[2][1] = z0[0][1] ^ z0[1][1] ^ mul2(z0[2][1]) ^ mul3(z0[3][1]); 
    w0[2][2] = z0[0][2] ^ z0[1][2] ^ mul2(z0[2][2]) ^ mul3(z0[3][2]); 
    w0[2][3] = z0[0][3] ^ z0[1][3] ^ mul2(z0[2][3]) ^ mul3(z0[3][3]);
    w0[3][0] = mul3(z0[0][0]) ^ z0[1][0] ^ z0[2][0] ^ mul2(z0[3][0]); 
    w0[3][1] = mul3(z0[0][1]) ^ z0[1][1] ^ z0[2][1] ^ mul2(z0[3][1]); 
    w0[3][2] = mul3(z0[0][2]) ^ z0[1][2] ^ z0[2][2] ^ mul2(z0[3][2]); 
    w0[3][3] = mul3(z0[0][3]) ^ z0[1][3] ^ z0[2][3] ^ mul2(z0[3][3]);
    z1[0][0] = sbox[x1[0][0]]; z1[0][2] = sbox[x1[0][2]]; 
    z1[1][0] = sbox[x1[1][1]]; z1[2][0] = sbox[x1[2][2]]; z1[3][0] = sbox[x1[3][3]];
    w1[0][0] = mul2(z1[0][0]) ^ mul3(z1[1][0]) ^ z1[2][0] ^ z1[3][0]; 
    w1[1][0] = z1[0][0] ^ mul2(z1[1][0]) ^ mul3(z1[2][0]) ^ z1[3][0];
    w1[2][0] = z1[0][0] ^ z1[1][0] ^ mul2(z1[2][0]) ^ mul3(z1[3][0]);
    w1[3][0] = mul3(z1[0][0]) ^ z1[1][0] ^ z1[2][0] ^ mul2(z1[3][0]);
    z2[0][0] = sbox[x2[0][0]]; z2[0][1] = sbox[x2[0][1]];
    z3[0][0] = sbox[x3[0][0]]; z3[0][1] = sbox[x3[0][1]];
    
    k1[0][0] = x1[0][0] ^ w0[0][0]; k1[0][2] = x1[0][2] ^ w0[0][2]; 
    k1[1][1] = x1[1][1] ^ w0[1][1]; k1[2][2] = x1[2][2] ^ w0[2][2]; k1[3][3] = x1[3][3] ^ w0[3][3];
    k2[0][0] = x2[0][0] ^ w1[0][0];

    // step2
    x1[0][1] = guessedBytes[0]; 
    x1[1][0] = guessedBytes[1]; x1[1][2] = guessedBytes[2]; x1[1][3] = guessedBytes[3];
    x1[2][0] = guessedBytes[4]; x1[2][1] = guessedBytes[5]; x1[2][3] = guessedBytes[6];
    x1[3][0] = guessedBytes[7]; x1[3][1] = guessedBytes[8]; x1[3][2] = guessedBytes[9];

    k1[0][1] = x1[0][1] ^ w0[0][1];
    k1[1][0] = x1[1][0] ^ w0[1][0]; k1[1][2] = x1[1][2] ^ w0[1][2]; k1[1][3] = x1[1][3] ^ w0[1][3];
    k1[2][0] = x1[2][0] ^ w0[2][0]; k1[2][1] = x1[2][1] ^ w0[2][1]; k1[2][3] = x1[2][3] ^ w0[2][3];
    k1[3][0] = x1[3][0] ^ w0[3][0]; k1[3][1] = x1[3][1] ^ w0[3][1]; k1[3][2] = x1[3][2] ^ w0[3][2];

    z1[0][1] = sbox[x1[0][1]]; 
    z1[1][1] = sbox[x1[1][2]]; z1[1][2] = sbox[x1[1][3]]; z1[1][3] = sbox[x1[1][0]];
    z1[2][1] = sbox[x1[2][3]]; z1[2][2] = sbox[x1[2][0]]; z1[2][3] = sbox[x1[2][1]];
    z1[3][1] = sbox[x1[3][0]]; z1[3][2] = sbox[x1[3][1]]; z1[3][3] = sbox[x1[3][2]];
    w1[0][1] = mul2(z1[0][1]) ^ mul3(z1[1][1]) ^ z1[2][1] ^ z1[3][1]; 
    w1[1][1] = z1[0][1] ^ mul2(z1[1][1]) ^ mul3(z1[2][1]) ^ z1[3][1];
    w1[2][1] = z1[0][1] ^ z1[1][1] ^ mul2(z1[2][1]) ^ mul3(z1[3][1]);
    w1[3][1] = mul3(z1[0][1]) ^ z1[1][1] ^ z1[2][1] ^ mul2(z1[3][1]);
    w1[0][2] = mul2(z1[0][2]) ^ mul3(z1[1][2]) ^ z1[2][2] ^ z1[3][2]; 
    w1[1][2] = z1[0][2] ^ mul2(z1[1][2]) ^ mul3(z1[2][2]) ^ z1[3][2];
    w1[2][2] = z1[0][2] ^ z1[1][2] ^ mul2(z1[2][2]) ^ mul3(z1[3][2]);
    w1[3][2] = mul3(z1[0][2]) ^ z1[1][2] ^ z1[2][2] ^ mul2(z1[3][2]);

    k2[0][1] = x2[0][1] ^ w1[0][1];

    // step 3
    k2[0][3] = guessedBytes[10]; k2[1][1] = guessedBytes[11]; k2[1][3] = guessedBytes[12]; k2[3][3] = guessedBytes[13];
    
    // query k2[2][3]
    k3[1][0] = sbox[k2[1][3]] ^ k1[1][0]; k3[1][1] = k3[1][0] ^ k1[1][1];
    k3[1][2] = k3[1][1] ^ k1[1][2]; k3[1][3] = k3[1][2] ^ k1[1][3];
    k5[1][3] = rsbox[0x04 ^ k6[0][3] ^ k2[0][1] ^ k2[0][3]];
    k5[1][2] = k5[1][3] ^ k3[1][3]; k5[1][1] = k5[1][2] ^ k3[1][2]; k5[1][0] = k5[1][1] ^ k3[1][1];
    k4[1][3] = rsbox[k5[1][0] ^ k3[1][0]]; k4[1][2] = k4[1][3] ^ k2[1][3];
    k3[2][3] = rsbox[w1[1][0] ^ k2[1][1] ^ w1[1][2] ^ k4[1][2]];
    k2[2][3] = rsbox[k3[2][3] ^ k1[2][0] ^ k1[2][1] ^ k1[2][2] ^ k1[2][3]];

    k3[0][0] = sbox[k2[0][3]] ^ k1[0][0]; k3[0][1] = k3[0][0] ^ k1[0][1]; k3[0][2] = k3[0][1] ^ k1[0][2];
    k3[2][0] = sbox[k2[2][3]] ^ k1[2][0]; k3[2][1] = k3[2][0] ^ k1[2][1]; k3[2][2] = k3[2][1] ^ k1[2][2];
    if (k3[2][3] != (k3[2][2] ^ k1[2][3])){
        printf("ERROR: k3[2][3] != k3[2][2] ^ k1[2][3]\n");
        return false;
    }
    k3[3][0] = sbox[k2[3][3]] ^ k1[3][0]; k3[3][1] = k3[3][0] ^ k1[3][1]; k3[3][2] = k3[3][1] ^ k1[3][2]; k3[3][3] = k3[3][2] ^ k1[3][3];
    k4[0][0] = sbox[k3[1][3]] ^ 0x02 ^ k2[0][0]; k4[0][1] = k4[0][0] ^ k2[0][1];
    x2[1][1] = k2[1][1] ^ w1[1][1]; z2[1][0] = sbox[x2[1][1]];
    w2[0][0] = k3[0][0] ^ x3[0][0]; w2[0][1] = k3[0][1] ^ x3[0][1];
    w3[0][0] = k4[0][0] ^ x4[0][0];

    // step 4
    k3[0][3] = sbox[k6[0][3]] ^ k7[0][3] ^ k3[0][1];
    k6[1][3] = rsbox[k3[1][1] ^ k3[1][3] ^ k7[1][3]];
    k6[2][3] = rsbox[k3[2][1] ^ k3[2][3] ^ k7[2][3]];
    k6[3][3] = rsbox[k3[3][1] ^ k3[3][3] ^ k7[3][3]];
    k1[0][3] = k3[0][2] ^ k3[0][3];
    x1[0][3] = k1[0][3] ^ w0[0][3]; z1[0][3] = sbox[x1[0][3]];
    w1[0][3] = mul2(z1[0][3]) ^ mul3(z1[1][3]) ^ z1[2][3] ^ z1[3][3];
    w1[1][3] = z1[0][3] ^ mul2(z1[1][3]) ^ mul3(z1[2][3]) ^ z1[3][3];
    w1[2][3] = z1[0][3] ^ z1[1][3] ^ mul2(z1[2][3]) ^ mul3(z1[3][3]);
    w1[3][3] = mul3(z1[0][3]) ^ z1[1][3] ^ z1[2][3] ^ mul2(z1[3][3]);
    x2[0][3] = k2[0][3] ^ w1[0][3]; z2[0][3] = sbox[x2[0][3]];
    x2[1][3] = k2[1][3] ^ w1[1][3]; z2[1][2] = sbox[x2[1][3]];
    x2[2][3] = k2[2][3] ^ w1[2][3]; z2[2][1] = sbox[x2[2][3]];
    x2[3][3] = k2[3][3] ^ w1[3][3]; z2[3][0] = sbox[x2[3][3]];
    
    // step 5
    k5[2][3] = rsbox[k6[1][3] ^ k2[1][1] ^ k2[1][3]];
    if (k5[1][3] != (rsbox[0x04 ^ k6[0][3] ^ k2[0][1] ^ k2[0][3]])){
        printf("ERROR: k5[1][3] != rsbox[k6[2][3] ^ k2[2][1] ^ k2[2][3]]\n");
        return false;
    }
    k5[2][2] = k5[2][3] ^ k3[2][3]; k5[2][1] = k5[2][2] ^ k3[2][2]; k5[2][0] = k5[2][1] ^ k3[2][1];
    k4[2][3] = rsbox[k5[2][0] ^ k3[2][0]]; k4[2][2] = k4[2][3] ^ k2[2][3];

    // step 6
    z2[2][0] = w2[0][0] ^ mul2(z2[0][0]) ^ mul3(z2[1][0]) ^ z2[3][0];
    w2[1][0] = z2[0][0] ^ mul2(z2[1][0]) ^ mul3(z2[2][0]) ^ z2[3][0];
    w2[2][0] = z2[0][0] ^ z2[1][0] ^ mul2(z2[2][0]) ^ mul3(z2[3][0]);
    w2[3][0] = mul3(z2[0][0]) ^ z2[1][0] ^ z2[2][0] ^ mul2(z2[3][0]);
    x2[2][2] = rsbox[z2[2][0]]; k2[2][2] = x2[2][2] ^ w1[2][2];
    k4[2][1] = k2[2][2] ^ k4[2][2];

    // step 7 query k2[2][1]
    k2[2][1] = w1[2][1] ^ rsbox[k3[3][3] ^ mul3(z2[0][3])];

    k4[2][0] = k4[2][1] ^ k2[2][1];
    k2[2][0] = k4[2][0] ^ sbox[k3[3][3]];
    k5[3][3] = rsbox[k6[2][3] ^ k2[2][1] ^ k2[2][3]];
    k5[3][2] = k5[3][3] ^ k3[3][3]; k5[3][1] = k5[3][2] ^ k3[3][2];
    k5[3][0] = k5[3][1] ^ k3[3][1]; k4[3][3] = rsbox[k5[3][0] ^ k3[3][0]]; 
    k4[3][2] = k4[3][3] ^ k2[3][3];

    x2[2][0] = k2[2][0] ^ w1[2][0]; x2[2][1] = k2[2][1] ^ w1[2][1]; 
    z2[2][2] = sbox[x2[2][0]]; z2[2][3] = sbox[x2[2][1]];

    // step 8 query k2[3][1]
    k2[3][1] = w1[3][0] ^ sbox[k3[0][3]] ^ w1[3][2] ^ k4[3][2];
    k5[0][3] = rsbox[k6[3][3] ^ k2[3][1] ^ k2[3][3]];
    k5[0][2] = k5[0][3] ^ k3[0][3]; k5[0][1] = k5[0][2] ^ k3[0][2]; k5[0][0] = k5[0][1] ^ k3[0][1];
    k4[0][3] = rsbox[k5[0][0] ^ k3[0][0]]; k4[0][2] = k4[0][3] ^ k2[0][3];
    k2[0][2] = k4[0][1] ^ k4[0][2];

    x2[3][1] = k2[3][1] ^ w1[3][1]; x2[0][2] = k2[0][2] ^ w1[0][2]; 
    z2[3][2] = sbox[x2[3][1]]; z2[0][2] = sbox[x2[0][2]];
    w2[0][2] = mul2(z2[0][2]) ^ mul3(z2[1][2]) ^ z2[2][2] ^ z2[3][2];
    w2[1][2] = z2[0][2] ^ mul2(z2[1][2]) ^ mul3(z2[2][2]) ^ z2[3][2];
    w2[2][2] = z2[0][2] ^ z2[1][2] ^ mul2(z2[2][2]) ^ mul3(z2[3][2]);
    w2[3][2] = mul3(z2[0][2]) ^ z2[1][2] ^ z2[2][2] ^ mul2(z2[3][2]);
    x3[2][2] = k3[2][2] ^ w2[2][2];
    z3[2][0] = sbox[x3[2][2]];

    // look up table
    uint8_t c2 = w2[0][1] ^ mul2(z2[0][1]) ^ z2[2][1];
    uint8_t c3 = k3[1][1] ^ z2[0][1] ^ mul3(z2[2][1]);
    uint8_t c5 = w3[0][0] ^ mul2(z3[0][0]) ^ z3[2][0];

    if (LookupTableExist[c2][c3][c5] == 0){
        // printf("ERROR: LookupTableExist[c2][c3][c5] == 0\n");
        return false;
    }

    x2[1][2] = LookupTable[c2][c3][c5]; k2[1][2] = x2[1][2] ^ w1[1][2];
    x2[1][0] = x2[1][2]; k2[1][0] = x2[1][0] ^ w1[1][0];

    x2[3][2] = rsbox[c2 ^ mul3(sbox[x2[1][2]])]; k2[3][2] = x2[3][2] ^ w1[3][2];
    x2[3][0] = x2[3][2]; k2[3][0] = x2[3][0] ^ w1[3][0];

    // calc K
    k0[0][1] = k2[0][0] ^ k2[0][1]; k0[0][2] = k2[0][1] ^ k2[0][2]; k0[0][3] = k2[0][2] ^ k2[0][3];
    k0[1][1] = k2[1][0] ^ k2[1][1]; k0[1][2] = k2[1][1] ^ k2[1][2]; k0[1][3] = k2[1][2] ^ k2[1][3];
    k0[2][1] = k2[2][0] ^ k2[2][1]; k0[2][2] = k2[2][1] ^ k2[2][2]; k0[2][3] = k2[2][2] ^ k2[2][3];
    k0[3][1] = k2[3][0] ^ k2[3][1]; k0[3][2] = k2[3][1] ^ k2[3][2]; k0[3][3] = k2[3][2] ^ k2[3][3];

    k0[0][0] = k2[0][0] ^ 0x01 ^ sbox[k1[1][3]];
    k0[1][0] = k2[1][0] ^ sbox[k1[2][3]];
    k0[2][0] = k2[2][0] ^ sbox[k1[3][3]];
    k0[3][0] = k2[3][0] ^ sbox[k1[0][3]];

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            plaintext[i * 4 + j] = k0[i][j] ^ x0[i][j];
        }
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            key[i * 4 + j] = k0[i][j];
            key[16 + i * 4 + j] = k1[i][j];
        }
    }
    
    return true;
}

void random_test(unsigned int seed){
    uint8_t guessedBytes[14];
    uint8_t plaintext[16];
    uint8_t key[32];

    uint64_t state = seed * 6364136223846793005ULL;
    state = xorshift64star(state);
    uint64_t count = 0;
    while (true){
        
        // Generate a random 14-byte key using the xorshift64* PRNG (8 bytes per call)
        for (int i = 0; i < 16; i += 8) {
            state = xorshift64star(state);
            uint64_t random_bytes = state;

            for (int j = 0; j < 8 && (i+j) < 14; j++) {
                guessedBytes[i + j] = (random_bytes >> (8*j)) & 0xFF;
            }
        }

        if (GDprocess(guessedBytes, plaintext, key)){
            count++;
            if (count % 10000000 == 0){
                printf("Random test count: %llu\n", count);
            }
            uint8_t test_plaintext[16];
            memcpy(test_plaintext, plaintext, 16);
            bool success = AES_256_12r(test_plaintext, key, true);


            if (!success){
                // printf("Verification failed.\n");
            } else {
                printf("Verification succeeded.\n");
                for (int i = 0; i < 16; i++){
                    printf("%02X ", plaintext[i]);
                }
                printf("\n");
                for (int i = 0; i < 32; i++){
                    printf("%02X ", key[i]);
                }
                printf("\n");

                printf("Random test passed.\n");

                uint8_t test_plaintext0[16], test_plaintext1[16];
                memcpy(test_plaintext0, plaintext, 16);
                memcpy(test_plaintext1, plaintext, 16);
                test_plaintext1[0] ^= 0xDA;
                uint8_t test_key0[32], test_key1[32];
                memcpy(test_key0, key, 32);
                memcpy(test_key1, key, 32);
                uint8_t key_diff[32] = {
                    0x2C, 0xF6, 0x2C, 0xF6,
                    0x7B, 0x7B, 0x7B, 0x7B,
                    0x7B, 0x7B, 0x7B, 0x7B,
                    0x8D, 0x8D, 0x8D, 0x8D,
                    0x5C, 0x00, 0x5C, 0x00,
                    0x34, 0x00, 0x34, 0x00,
                    0x34, 0x00, 0x34, 0x00,
                    0x5C, 0x00, 0x5C, 0x00
                };

                for (int i = 0; i < 32; i++){
                    test_key1[i] ^= key_diff[i];
                }

                uint8_t roundKey0[8][4][4];
                uint8_t roundKey1[8][4][4];

                verify5rAES(test_plaintext0, test_key0, roundKey0, 6);
                verify5rAES(test_plaintext1, test_key1, roundKey1, 6);

                for (int i = 0; i < 4; i++){
                    for (int j = 0; j < 4; j++){
                        printf("%02x ", test_plaintext0[i * 4 + j] ^ test_plaintext1[i * 4 + j]);
                    }
                    printf("\n");
                }
                printf("\n");
                break;
            }
        }

    }
}

int main(){
    MakeTable();
    printf("LookupTable generated.\n");

    unsigned int base_seed = (unsigned int)time(NULL);
    random_test(base_seed);

    return 0;
}