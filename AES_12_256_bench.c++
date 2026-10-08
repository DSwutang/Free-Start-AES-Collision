#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#if defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#define HAS_ARM_AESE 1
#else
#define HAS_ARM_AESE 0
#endif

#define main AES_12_256_original_main
#include "AES_12_256.c++"
#undef main

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

static volatile uint64_t bench_sink = 0;

#if HAS_ARM_AESE
NOINLINE static bool AES_256_12r_AESE_verify(uint8_t plaintext[16], const uint8_t key[32], bool checkCondition);
#endif

static double elapsedSeconds(std::chrono::steady_clock::time_point begin,
                             std::chrono::steady_clock::time_point end){
    return std::chrono::duration<double>(end - begin).count();
}

static void printRate(const char* name, uint64_t iterations, double seconds, uint64_t checksum){
    double ns_per_iter = seconds * 1e9 / (double)iterations;
    double iters_per_sec = (double)iterations / seconds;
    printf("%s\n", name);
    printf("  iterations: %llu\n", (unsigned long long)iterations);
    printf("  seconds:    %.6f\n", seconds);
    printf("  ns/iter:    %.3f\n", ns_per_iter);
    printf("  iter/sec:   %.3f\n", iters_per_sec);
    printf("  checksum:   %llu\n", (unsigned long long)checksum);
}

NOINLINE static bool GDprocessInboundFast(const uint8_t* guessedBytes, uint8_t* plaintext, uint8_t* key,
                                          uint8_t (*x2Out)[4] = NULL,
                                          uint8_t (*k2Out)[4] = NULL,
                                          uint8_t (*k3Out)[4] = NULL){
    uint8_t k0[4][4], k1[4][4], k2[4][4], k3[4][4], k4[4][4], k5[4][4], k6[4][4], k7[4][4];
    uint8_t x0[4][4], x1[4][4], x2[4][4], x3[4][4], x4[4][4];
    uint8_t z0[4][4], z1[4][4], z2[4][4], z3[4][4], z4[4][4];
    uint8_t w0[4][4], w1[4][4], w2[4][4], w3[4][4];

    x0[0][0] = 0x00; x0[0][1] = 0x66; x0[0][2] = 0x00; x0[0][3] = 0x00;
    x0[1][0] = 0x82; x0[1][1] = 0xAA; x0[1][2] = 0x19; x0[1][3] = 0x00;
    x0[2][0] = 0x31; x0[2][1] = 0x24; x0[2][2] = 0x34; x0[2][3] = 0x09;
    x0[3][0] = 0x0F; x0[3][1] = 0x43; x0[3][2] = 0x00; x0[3][3] = 0x26;

    x1[0][0] = 0x63; x1[0][2] = 0xD2; x1[1][1] = 0x00; x1[2][2] = 0x01; x1[3][3] = 0xA1;
    x2[0][0] = 0xC2; x2[0][1] = 0x00;
    x3[0][0] = 0x00; x3[0][1] = 0x00;
    x4[0][0] = 0x00;

    k6[0][3] = 0x00; k7[0][3] = 0xAC; k7[1][3] = 0x04; k7[2][3] = 0x00; k7[3][3] = 0x2D;

    w0[0][0] = 0xC6; w0[0][1] = 0x76; w0[0][2] = 0xBE; w0[0][3] = 0xA6;
    w0[1][0] = 0xFF; w0[1][1] = 0xF5; w0[1][2] = 0xED; w0[1][3] = 0x7C;
    w0[2][0] = 0xFD; w0[2][1] = 0x7F; w0[2][2] = 0xBB; w0[2][3] = 0xB9;
    w0[3][0] = 0xE4; w0[3][1] = 0x6C; w0[3][2] = 0x35; w0[3][3] = 0x46;
    z1[0][0] = 0xFB; z1[0][2] = 0xB5;
    z1[1][0] = 0x63; z1[2][0] = 0x7C; z1[3][0] = 0x32;
    w1[0][0] = 0x06; w1[1][0] = 0x8B; w1[2][0] = 0x36; w1[3][0] = 0x6D;
    z2[0][0] = 0x25; z2[0][1] = 0x63;
    z3[0][0] = 0x63; z3[0][1] = 0x63;
    
    k1[0][0] = 0xA5; k1[0][2] = 0x6C;
    k1[1][1] = 0xF5; k1[2][2] = 0xBA; k1[3][3] = 0xE7;
    k2[0][0] = 0xC4;

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
    k2[0][3] = guessedBytes[10]; k2[1][1] = guessedBytes[11]; k2[1][3] = guessedBytes[12]; k2[3][3] = guessedBytes[13];
    
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
        return false;
    }
    k3[3][0] = sbox[k2[3][3]] ^ k1[3][0]; k3[3][1] = k3[3][0] ^ k1[3][1]; k3[3][2] = k3[3][1] ^ k1[3][2]; k3[3][3] = k3[3][2] ^ k1[3][3];
    k4[0][0] = sbox[k3[1][3]] ^ 0x02 ^ k2[0][0]; k4[0][1] = k4[0][0] ^ k2[0][1];
    x2[1][1] = k2[1][1] ^ w1[1][1]; z2[1][0] = sbox[x2[1][1]];
    w2[0][0] = k3[0][0] ^ x3[0][0]; w2[0][1] = k3[0][1] ^ x3[0][1];
    w3[0][0] = k4[0][0] ^ x4[0][0];

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
    
    k5[2][3] = rsbox[k6[1][3] ^ k2[1][1] ^ k2[1][3]];
    if (k5[1][3] != (rsbox[0x04 ^ k6[0][3] ^ k2[0][1] ^ k2[0][3]])){
        return false;
    }
    k5[2][2] = k5[2][3] ^ k3[2][3]; k5[2][1] = k5[2][2] ^ k3[2][2]; k5[2][0] = k5[2][1] ^ k3[2][1];
    k4[2][3] = rsbox[k5[2][0] ^ k3[2][0]]; k4[2][2] = k4[2][3] ^ k2[2][3];

    z2[2][0] = w2[0][0] ^ mul2(z2[0][0]) ^ mul3(z2[1][0]) ^ z2[3][0];
    w2[1][0] = z2[0][0] ^ mul2(z2[1][0]) ^ mul3(z2[2][0]) ^ z2[3][0];
    w2[2][0] = z2[0][0] ^ z2[1][0] ^ mul2(z2[2][0]) ^ mul3(z2[3][0]);
    w2[3][0] = mul3(z2[0][0]) ^ z2[1][0] ^ z2[2][0] ^ mul2(z2[3][0]);
    x2[2][2] = rsbox[z2[2][0]]; k2[2][2] = x2[2][2] ^ w1[2][2];
    k4[2][1] = k2[2][2] ^ k4[2][2];
    k2[2][1] = w1[2][1] ^ rsbox[k3[3][3] ^ mul3(z2[0][3])];

    k4[2][0] = k4[2][1] ^ k2[2][1];
    k2[2][0] = k4[2][0] ^ sbox[k3[3][3]];
    k5[3][3] = rsbox[k6[2][3] ^ k2[2][1] ^ k2[2][3]];
    k5[3][2] = k5[3][3] ^ k3[3][3]; k5[3][1] = k5[3][2] ^ k3[3][2];
    k5[3][0] = k5[3][1] ^ k3[3][1]; k4[3][3] = rsbox[k5[3][0] ^ k3[3][0]]; 
    k4[3][2] = k4[3][3] ^ k2[3][3];

    x2[2][0] = k2[2][0] ^ w1[2][0]; x2[2][1] = k2[2][1] ^ w1[2][1]; 
    z2[2][2] = sbox[x2[2][0]]; z2[2][3] = sbox[x2[2][1]];

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

    uint8_t c2 = w2[0][1] ^ mul2(z2[0][1]) ^ z2[2][1];
    uint8_t c3 = k3[1][1] ^ z2[0][1] ^ mul3(z2[2][1]);
    uint8_t c5 = w3[0][0] ^ mul2(z3[0][0]) ^ z3[2][0];

    uint8_t lookupB = LookupTable[c2][c3][c5];
    uint8_t lookupSB = sbox[lookupB];
    uint8_t lookupS = c2 ^ c3 ^ lookupSB;
    uint8_t lookupR = mul2(c2) ^ mul7(lookupSB);
    uint8_t lookupC5 = mul3(sbox[lookupS]) ^ sbox[lookupR];
    if (lookupC5 != c5){
        return false;
    }

    if (plaintext == NULL && key == NULL && x2Out == NULL && k2Out == NULL && k3Out == NULL){
        return true;
    }

    x2[1][2] = lookupB; k2[1][2] = x2[1][2] ^ w1[1][2];
    x2[1][0] = x2[1][2]; k2[1][0] = x2[1][0] ^ w1[1][0];

    x2[3][2] = rsbox[c2 ^ mul3(sbox[x2[1][2]])]; k2[3][2] = x2[3][2] ^ w1[3][2];
    x2[3][0] = x2[3][2]; k2[3][0] = x2[3][0] ^ w1[3][0];

    if (x2Out != NULL){
        memcpy(x2Out, x2, 16);
    }
    if (k2Out != NULL){
        memcpy(k2Out, k2, 16);
    }
    if (k3Out != NULL){
        memcpy(k3Out, k3, 16);
    }

    if (plaintext == NULL || key == NULL){
        return true;
    }

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

static void aesSubShiftMix(uint8_t state[4][4], bool mixColumns){
    uint8_t tstate[4];

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

    if (mixColumns){
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

static uint8_t aesMixByteAfterSubShift(const uint8_t state[4][4], int row, int col){
    uint8_t a0 = sbox[state[0][col]];
    uint8_t a1 = sbox[state[1][(col + 1) & 3]];
    uint8_t a2 = sbox[state[2][(col + 2) & 3]];
    uint8_t a3 = sbox[state[3][(col + 3) & 3]];

    if (row == 0){
        return mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
    }
    if (row == 1){
        return a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
    }
    if (row == 2){
        return a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
    }
    return mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
}

static void addRoundKeyFromKeyBlock(uint8_t state[4][4], const uint8_t keyBlock[7][32], int r){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            int word = 4 * r + j;
            state[i][j] ^= keyBlock[word / 8][8 * i + word % 8];
        }
    }
}

static void initKeyBlockFromK2K3(const uint8_t k2[4][4], const uint8_t k3[4][4],
                                 uint8_t keyBlock[7][32]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            keyBlock[1][8 * i + j] = k2[i][j];
            keyBlock[1][8 * i + 4 + j] = k3[i][j];
        }
    }
}

static void expandKeyBlockBlocks(uint8_t keyBlock[7][32], int beginBlock, int endBlock){
    for (int i = beginBlock; i < endBlock; i++){
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
}

static void expandKeyBlockFromK2K3(const uint8_t k2[4][4], const uint8_t k3[4][4],
                                   uint8_t keyBlock[7][32]){
    initKeyBlockFromK2K3(k2, k3, keyBlock);
    expandKeyBlockBlocks(keyBlock, 2, 7);
}

NOINLINE static bool AES_256_12r_from_x2_k2_k3(const uint8_t x2[4][4],
                                               const uint8_t k2[4][4],
                                               const uint8_t k3[4][4],
                                               uint8_t ciphertext[4][4],
                                               bool checkCondition){
    uint8_t keyBlock[7][32];
    uint8_t state[4][4];

    initKeyBlockFromK2K3(k2, k3, keyBlock);
    if (!checkCondition){
        expandKeyBlockBlocks(keyBlock, 2, 7);
        memcpy(state, x2, 16);
        for (int r = 2; r < 12; r++){
            if (r != 2){
                for (int i = 0; i < 4; i++){
                    for (int j = 0; j < 4; j++){
                        int word = 4 * r + j;
                        state[i][j] ^= keyBlock[word / 8][8 * i + word % 8];
                    }
                }
            }
            aesSubShiftMix(state, r != 11);
        }
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                int word = 48 + j;
                state[i][j] ^= keyBlock[word / 8][8 * i + word % 8];
            }
        }
        memcpy(ciphertext, state, 16);
        return true;
    }

    memcpy(state, x2, 16);

    aesSubShiftMix(state, true);

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] ^= k3[i][j];
        }
    }

    uint8_t k4_00 = sbox[k3[1][3]] ^ 0x02 ^ k2[0][0];
    uint8_t k4_01 = k4_00 ^ k2[0][1];
    uint8_t k4_02 = k4_01 ^ k2[0][2];
    uint8_t k4_03 = k4_02 ^ k2[0][3];
    uint8_t k5_00 = k3[0][0] ^ sbox[k4_03];

    uint8_t k4_10 = sbox[k3[2][3]] ^ k2[1][0];
    uint8_t k4_11 = k4_10 ^ k2[1][1];
    uint8_t k4_20 = sbox[k3[3][3]] ^ k2[2][0];
    uint8_t k4_21 = k4_20 ^ k2[2][1];
    uint8_t k4_22 = k4_21 ^ k2[2][2];
    uint8_t k4_30 = sbox[k3[0][3]] ^ k2[3][0];
    uint8_t k4_31 = k4_30 ^ k2[3][1];
    uint8_t k4_32 = k4_31 ^ k2[3][2];
    uint8_t k4_33 = k4_32 ^ k2[3][3];

    uint8_t x4_00 = aesMixByteAfterSubShift(state, 0, 0) ^ k4_00;
    uint8_t x4_11 = aesMixByteAfterSubShift(state, 1, 1) ^ k4_11;
    uint8_t x4_22 = aesMixByteAfterSubShift(state, 2, 2) ^ k4_22;
    uint8_t x4_33 = aesMixByteAfterSubShift(state, 3, 3) ^ k4_33;

    uint8_t w4_00 = mul2(sbox[x4_00]) ^ mul3(sbox[x4_11]) ^ sbox[x4_22] ^ sbox[x4_33];
    uint8_t x5_00 = w4_00 ^ k5_00;
    if (!allowed34to7b(x5_00)){
        return false;
    }

    expandKeyBlockBlocks(keyBlock, 2, 3);

    aesSubShiftMix(state, true);
    addRoundKeyFromKeyBlock(state, keyBlock, 4);
    aesSubShiftMix(state, true);
    addRoundKeyFromKeyBlock(state, keyBlock, 5);

    uint8_t k6_00 = sbox[keyBlock[2][15]] ^ 0x04 ^ keyBlock[2][0];
    uint8_t k6_01 = k6_00 ^ keyBlock[2][1];
    uint8_t k6_02 = k6_01 ^ keyBlock[2][2];
    uint8_t k6_03 = k6_02 ^ keyBlock[2][3];

    uint8_t x6_00 = aesMixByteAfterSubShift(state, 0, 0) ^ k6_00;
    uint8_t x6_01 = aesMixByteAfterSubShift(state, 0, 1) ^ k6_01;
    uint8_t x6_02 = aesMixByteAfterSubShift(state, 0, 2) ^ k6_02;
    uint8_t x6_03 = aesMixByteAfterSubShift(state, 0, 3) ^ k6_03;
    if (!allowedDato34(x6_00) || !allowedDato34(x6_01) ||
        !allowedDato34(x6_02) || !allowedDato34(x6_03)){
        return false;
    }

    expandKeyBlockBlocks(keyBlock, 3, 7);
    aesSubShiftMix(state, true);
    addRoundKeyFromKeyBlock(state, keyBlock, 6);

    aesSubShiftMix(state, true);

    for (int r = 7; r < 12; r++){
        addRoundKeyFromKeyBlock(state, keyBlock, r);
        if (r == 8 && (!allowedDato34(state[0][0]) || !allowedDato34(state[0][2]))){
            return false;
        }
        if (r == 8){
            return true;
        }
        aesSubShiftMix(state, r != 11);
    }

    addRoundKeyFromKeyBlock(state, keyBlock, 12);

    memcpy(ciphertext, state, 16);
    return true;
}

NOINLINE static bool AES_256_12r_from_x2_k2_k3_oldloop(const uint8_t x2[4][4],
                                                       const uint8_t k2[4][4],
                                                       const uint8_t k3[4][4],
                                                       uint8_t ciphertext[4][4],
                                                       bool checkCondition){
    uint8_t keyBlock[7][32];
    uint8_t state[4][4];

    initKeyBlockFromK2K3(k2, k3, keyBlock);
    if (checkCondition){
        expandKeyBlockBlocks(keyBlock, 2, 4);
    }
    else{
        expandKeyBlockBlocks(keyBlock, 2, 7);
    }
    memcpy(state, x2, 16);

    for (int r = 2; r < 12; r++){
        if (r != 2){
            for (int i = 0; i < 4; i++){
                for (int j = 0; j < 4; j++){
                    int word = 4 * r + j;
                    state[i][j] ^= keyBlock[word / 8][8 * i + word % 8];
                }
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
            if (r == 6){
                expandKeyBlockBlocks(keyBlock, 4, 7);
            }
        }

        aesSubShiftMix(state, r != 11);
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            int word = 48 + j;
            state[i][j] ^= keyBlock[word / 8][8 * i + word % 8];
        }
    }

    memcpy(ciphertext, state, 16);
    return true;
}

NOINLINE static bool AES_256_12r_from_x2_k2_k3_check568_reference(const uint8_t x2[4][4],
                                                                  const uint8_t k2[4][4],
                                                                  const uint8_t k3[4][4]){
    uint8_t keyBlock[7][32];
    uint8_t state[4][4];

    expandKeyBlockFromK2K3(k2, k3, keyBlock);
    memcpy(state, x2, 16);

    for (int r = 2; r <= 8; r++){
        if (r != 2){
            addRoundKeyFromKeyBlock(state, keyBlock, r);
        }
        if (r == 5 && !allowed34to7b(state[0][0])){
            return false;
        }
        if (r == 6 && (!allowedDato34(state[0][0]) || !allowedDato34(state[0][1]) ||
                       !allowedDato34(state[0][2]) || !allowedDato34(state[0][3]))){
            return false;
        }
        if (r == 8){
            return allowedDato34(state[0][0]) && allowedDato34(state[0][2]);
        }
        aesSubShiftMix(state, true);
    }

    return false;
}

NOINLINE static bool oneGDAndMaybeAES(uint64_t* rng_state, uint64_t* checksum){
    uint8_t guessedBytes[14];
    uint8_t plaintext[16];
    uint8_t key[32];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    bool gd_ok = GDprocess(guessedBytes, plaintext, key);
    *checksum += gd_ok;

    if (gd_ok){
        uint8_t test_plaintext[16];
        memcpy(test_plaintext, plaintext, 16);
#if HAS_ARM_AESE
        bool aes_ok = AES_256_12r_AESE_verify(test_plaintext, key, true);
#else
        bool aes_ok = AES_256_12r(test_plaintext, key, true);
#endif
        *checksum += ((uint64_t)aes_ok << 8) ^ test_plaintext[0] ^ key[0];
        return aes_ok;
    }

    return false;
}

NOINLINE static bool oneGDAndOriginalAES(uint64_t* rng_state, uint64_t* checksum,
                                         bool* gd_ok_out){
    uint8_t guessedBytes[14];
    uint8_t plaintext[16];
    uint8_t key[32];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    bool gd_ok = GDprocess(guessedBytes, plaintext, key);
    *gd_ok_out = gd_ok;

    if (gd_ok){
        uint8_t test_plaintext[16];
        memcpy(test_plaintext, plaintext, 16);
        bool aes_ok = AES_256_12r(test_plaintext, key, true);
        *checksum += 1 + ((uint64_t)aes_ok << 8) + test_plaintext[0] + key[0];
        return aes_ok;
    }

    return false;
}

NOINLINE static bool oneGDOnly(uint64_t* rng_state){
    uint8_t guessedBytes[14];
    uint8_t plaintext[16];
    uint8_t key[32];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    return GDprocess(guessedBytes, plaintext, key);
}

NOINLINE static bool oneGDInboundFast(uint64_t* rng_state){
    uint8_t guessedBytes[14];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    return GDprocessInboundFast(guessedBytes, NULL, NULL);
}

NOINLINE static bool oneGDFastReconstruct(uint64_t* rng_state, uint64_t* checksum){
    uint8_t guessedBytes[14];
    uint8_t plaintext[16];
    uint8_t key[32];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    bool gd_ok = GDprocessInboundFast(guessedBytes, plaintext, key);
    if (gd_ok){
        *checksum += 1 + plaintext[0] + plaintext[7] + plaintext[15] + key[0] + key[17] + key[31];
    }
    return gd_ok;
}

NOINLINE static bool oneOriginalFlowCountGD(uint64_t* rng_state, uint64_t* checksum,
                                            bool* aes_ok_out){
    uint8_t guessedBytes[14];
    uint8_t plaintext[16];
    uint8_t key[32];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    bool gd_ok = GDprocess(guessedBytes, plaintext, key);
    *aes_ok_out = false;

    if (gd_ok){
        uint8_t test_plaintext[16];
        memcpy(test_plaintext, plaintext, 16);
#if HAS_ARM_AESE
        bool aes_ok = AES_256_12r_AESE_verify(test_plaintext, key, true);
#else
        bool aes_ok = AES_256_12r(test_plaintext, key, true);
#endif
        *aes_ok_out = aes_ok;
        *checksum += 1 + ((uint64_t)aes_ok << 8) + test_plaintext[0] + key[0];
    }

    return gd_ok;
}

NOINLINE static bool oneGDMidFastVerify(uint64_t* rng_state, uint64_t* checksum,
                                        bool* gd_ok_out){
    uint8_t guessedBytes[14];
    uint8_t x2[4][4], k2[4][4], k3[4][4];
    uint8_t ciphertext[4][4];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    bool gd_ok = GDprocessInboundFast(guessedBytes, NULL, NULL, x2, k2, k3);
    *gd_ok_out = gd_ok;

    if (gd_ok){
        bool aes_ok = AES_256_12r_from_x2_k2_k3(x2, k2, k3, ciphertext, true);
        *checksum += 1 + ((uint64_t)aes_ok << 8);
        if (aes_ok){
            *checksum += ciphertext[0][0] + ciphertext[1][3] + ciphertext[3][3];
        }
        return aes_ok;
    }

    return false;
}

NOINLINE static bool oneGDMidOnly(uint64_t* rng_state, uint64_t* checksum){
    uint8_t guessedBytes[14];
    uint8_t x2[4][4], k2[4][4], k3[4][4];

    for (int i = 0; i < 16; i += 8){
        *rng_state = xorshift64star(*rng_state);
        uint64_t random_bytes = *rng_state;
        for (int j = 0; j < 8 && (i + j) < 14; j++){
            guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
        }
    }

    bool gd_ok = GDprocessInboundFast(guessedBytes, NULL, NULL, x2, k2, k3);
    if (gd_ok){
        *checksum += 1 + x2[0][0] + x2[1][2] + x2[3][3] + k2[0][0] + k3[3][3];
    }
    return gd_ok;
}

static void benchmarkGDOnly(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t gd_success = 0;

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        gd_success += oneGDOnly(&rng_state);
    }
    auto end = std::chrono::steady_clock::now();

    uint64_t checksum = rng_state ^ (gd_success << 1);
    bench_sink ^= checksum;

    printRate("GDprocess only, count inbound success", iterations,
              elapsedSeconds(begin, end), checksum);
    printf("  inbound accepted: %llu\n", (unsigned long long)gd_success);
}

static void benchmarkGDAndMaybeAES(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t gd_success = 0;
    uint64_t aes_success = 0;

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        uint64_t before = checksum;
        bool ok = oneGDAndMaybeAES(&rng_state, &checksum);
        gd_success += (checksum != before);
        aes_success += ok;
    }
    auto end = std::chrono::steady_clock::now();

    checksum ^= rng_state ^ (gd_success << 1) ^ (aes_success << 2);
    bench_sink ^= checksum;

#if HAS_ARM_AESE
    printRate("GDprocess + conditional AESE AES_256_12r(checkCondition=true)", iterations,
              elapsedSeconds(begin, end), checksum);
#else
    printRate("GDprocess + conditional AES_256_12r(checkCondition=true)", iterations,
              elapsedSeconds(begin, end), checksum);
#endif
    printf("  GD accepted: %llu\n", (unsigned long long)gd_success);
    printf("  AES accepted: %llu\n", (unsigned long long)aes_success);
}

static void benchmarkGDAndOriginalAES(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t gd_success = 0;
    uint64_t aes_success = 0;

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        bool gd_ok = false;
        bool aes_ok = oneGDAndOriginalAES(&rng_state, &checksum, &gd_ok);
        gd_success += gd_ok;
        aes_success += aes_ok;
    }
    auto end = std::chrono::steady_clock::now();

    checksum ^= rng_state ^ (gd_success << 1) ^ (aes_success << 2);
    bench_sink ^= checksum;

    printRate("Original GDprocess + conditional original AES_256_12r(checkCondition=true)", iterations,
              elapsedSeconds(begin, end), checksum);
    printf("  GD accepted: %llu\n", (unsigned long long)gd_success);
    printf("  AES accepted: %llu\n", (unsigned long long)aes_success);
}

static void benchmarkUntilGDSuccessOriginalAES(uint64_t target_success){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t attempts = 0;
    uint64_t gd_success = 0;
    uint64_t aes_success = 0;

    auto begin = std::chrono::steady_clock::now();
    while (gd_success < target_success){
        bool gd_ok = false;
        bool aes_ok = oneGDAndOriginalAES(&rng_state, &checksum, &gd_ok);
        attempts++;
        if (gd_ok){
            gd_success++;
            aes_success += aes_ok;
        }
    }
    auto end = std::chrono::steady_clock::now();

    double seconds = elapsedSeconds(begin, end);
    checksum ^= rng_state ^ attempts ^ (gd_success << 1) ^ (aes_success << 2);
    bench_sink ^= checksum;

    printf("Original GDprocess successes + conditional original AES_256_12r(checkCondition=true)\n");
    printf("  target GD successes: %llu\n", (unsigned long long)target_success);
    printf("  total attempts:      %llu\n", (unsigned long long)attempts);
    printf("  seconds:             %.6f\n", seconds);
    printf("  ns/GD success:       %.3f\n", seconds * 1e9 / (double)gd_success);
    printf("  attempts/sec:        %.3f\n", (double)attempts / seconds);
    printf("  GD success/sec:      %.3f\n", (double)gd_success / seconds);
    printf("  attempts/GD success: %.6f\n", (double)attempts / (double)gd_success);
    printf("  AES accepted:        %llu\n", (unsigned long long)aes_success);
    printf("  checksum:            %llu\n", (unsigned long long)checksum);
}

static void benchmarkGDMidOnly(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t gd_success = 0;

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        gd_success += oneGDMidOnly(&rng_state, &checksum);
    }
    auto end = std::chrono::steady_clock::now();

    checksum ^= rng_state ^ (gd_success << 1);
    bench_sink ^= checksum;

    printRate("GDprocessInboundFast -> x2/k2/k3 only, no AES verification", iterations,
              elapsedSeconds(begin, end), checksum);
    printf("  GD accepted: %llu\n", (unsigned long long)gd_success);
}

static void benchmarkGDMidFastVerify(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t gd_success = 0;
    uint64_t aes_success = 0;

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        bool gd_ok = false;
        bool aes_ok = oneGDMidFastVerify(&rng_state, &checksum, &gd_ok);
        gd_success += gd_ok;
        aes_success += aes_ok;
    }
    auto end = std::chrono::steady_clock::now();

    checksum ^= rng_state ^ (gd_success << 1) ^ (aes_success << 2);
    bench_sink ^= checksum;

    printRate("GDprocessInboundFast -> x2/k2/k3 + AES_256_12r_from_x2(checkCondition=true)", iterations,
              elapsedSeconds(begin, end), checksum);
    printf("  GD accepted: %llu\n", (unsigned long long)gd_success);
    printf("  AES accepted: %llu\n", (unsigned long long)aes_success);
}

static void benchmarkUntilGDSuccessMidFastVerify(uint64_t target_success){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t attempts = 0;
    uint64_t gd_success = 0;
    uint64_t aes_success = 0;

    auto begin = std::chrono::steady_clock::now();
    while (gd_success < target_success){
        bool gd_ok = false;
        bool aes_ok = oneGDMidFastVerify(&rng_state, &checksum, &gd_ok);
        attempts++;
        if (gd_ok){
            gd_success++;
            aes_success += aes_ok;
        }
    }
    auto end = std::chrono::steady_clock::now();

    double seconds = elapsedSeconds(begin, end);
    checksum ^= rng_state ^ attempts ^ (gd_success << 1) ^ (aes_success << 2);
    bench_sink ^= checksum;

    printf("GDprocessInboundFast successes -> x2/k2/k3 + fast AES_256_12r_from_x2(checkCondition=true)\n");
    printf("  target GD successes: %llu\n", (unsigned long long)target_success);
    printf("  total attempts:      %llu\n", (unsigned long long)attempts);
    printf("  seconds:             %.6f\n", seconds);
    printf("  ns/GD success:       %.3f\n", seconds * 1e9 / (double)gd_success);
    printf("  attempts/sec:        %.3f\n", (double)attempts / seconds);
    printf("  GD success/sec:      %.3f\n", (double)gd_success / seconds);
    printf("  attempts/GD success: %.6f\n", (double)attempts / (double)gd_success);
    printf("  AES accepted:        %llu\n", (unsigned long long)aes_success);
    printf("  checksum:            %llu\n", (unsigned long long)checksum);
}

static void benchmarkUntilGDSuccessOnly(uint64_t target_success){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t attempts = 0;
    uint64_t gd_success = 0;

    auto begin = std::chrono::steady_clock::now();
    while (gd_success < target_success){
        gd_success += oneGDOnly(&rng_state);
        attempts++;
    }
    auto end = std::chrono::steady_clock::now();

    double seconds = elapsedSeconds(begin, end);
    uint64_t checksum = rng_state ^ attempts ^ (gd_success << 1);
    bench_sink ^= checksum;

    printf("GDprocess only, count inbound successes\n");
    printf("  target inbound successes: %llu\n", (unsigned long long)target_success);
    printf("  total attempts:           %llu\n", (unsigned long long)attempts);
    printf("  seconds:                  %.6f\n", seconds);
    printf("  ns/inbound success:       %.3f\n", seconds * 1e9 / (double)gd_success);
    printf("  attempts/sec:             %.3f\n", (double)attempts / seconds);
    printf("  inbound success/sec:      %.3f\n", (double)gd_success / seconds);
    printf("  attempts/inbound success: %.6f\n", (double)attempts / (double)gd_success);
    printf("  checksum:                 %llu\n", (unsigned long long)checksum);
}

static void benchmarkUntilGDSuccessFast(uint64_t target_success){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t attempts = 0;
    uint64_t gd_success = 0;

    auto begin = std::chrono::steady_clock::now();
    while (gd_success < target_success){
        gd_success += oneGDInboundFast(&rng_state);
        attempts++;
    }
    auto end = std::chrono::steady_clock::now();

    double seconds = elapsedSeconds(begin, end);
    uint64_t checksum = rng_state ^ attempts ^ (gd_success << 1);
    bench_sink ^= checksum;

    printf("GDprocessInboundFast only, count inbound successes\n");
    printf("  target inbound successes: %llu\n", (unsigned long long)target_success);
    printf("  total attempts:           %llu\n", (unsigned long long)attempts);
    printf("  seconds:                  %.6f\n", seconds);
    printf("  ns/inbound success:       %.3f\n", seconds * 1e9 / (double)gd_success);
    printf("  attempts/sec:             %.3f\n", (double)attempts / seconds);
    printf("  inbound success/sec:      %.3f\n", (double)gd_success / seconds);
    printf("  attempts/inbound success: %.6f\n", (double)attempts / (double)gd_success);
    printf("  checksum:                 %llu\n", (unsigned long long)checksum);
}

static bool checkGDInboundFast(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t original_success = 0;
    uint64_t fast_success = 0;
    uint64_t mismatch = 0;
    uint64_t checksum = 0;

    for (uint64_t n = 0; n < iterations; n++){
        uint8_t guessedBytes[14];
        uint8_t plaintext[16];
        uint8_t key[32];

        for (int i = 0; i < 16; i += 8){
            rng_state = xorshift64star(rng_state);
            uint64_t random_bytes = rng_state;
            for (int j = 0; j < 8 && (i + j) < 14; j++){
                guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
            }
        }

        bool original_ok = GDprocess(guessedBytes, plaintext, key);
        bool fast_ok = GDprocessInboundFast(guessedBytes, NULL, NULL);

        original_success += original_ok;
        fast_success += fast_ok;
        checksum += ((uint64_t)original_ok << 1) ^ fast_ok ^ guessedBytes[0] ^ guessedBytes[13];

        if (original_ok != fast_ok){
            mismatch++;
            printf("Mismatch at sample %llu\n", (unsigned long long)n);
            printf("guessedBytes:");
            for (int i = 0; i < 14; i++){
                printf(" %02x", guessedBytes[i]);
            }
            printf("\n");
            printf("original: %d, fast: %d\n", (int)original_ok, (int)fast_ok);
            break;
        }
    }

    bench_sink ^= checksum ^ original_success ^ (fast_success << 1) ^ mismatch;
    printf("GDprocessInboundFast correctness check\n");
    printf("  samples:          %llu\n", (unsigned long long)iterations);
    printf("  original success: %llu\n", (unsigned long long)original_success);
    printf("  fast success:     %llu\n", (unsigned long long)fast_success);
    printf("  mismatch:         %llu\n", (unsigned long long)mismatch);
    printf("  checksum:         %llu\n", (unsigned long long)checksum);
    return mismatch == 0;
}

static bool checkGDFastReconstruct(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t original_success = 0;
    uint64_t fast_success = 0;
    uint64_t mismatch = 0;
    uint64_t checksum = 0;

    for (uint64_t n = 0; n < iterations; n++){
        uint8_t guessedBytes[14];
        uint8_t plaintext0[16], plaintext1[16];
        uint8_t key0[32], key1[32];

        memset(plaintext0, 0, sizeof(plaintext0));
        memset(plaintext1, 0, sizeof(plaintext1));
        memset(key0, 0, sizeof(key0));
        memset(key1, 0, sizeof(key1));

        for (int i = 0; i < 16; i += 8){
            rng_state = xorshift64star(rng_state);
            uint64_t random_bytes = rng_state;
            for (int j = 0; j < 8 && (i + j) < 14; j++){
                guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
            }
        }

        bool original_ok = GDprocess(guessedBytes, plaintext0, key0);
        bool fast_ok = GDprocessInboundFast(guessedBytes, plaintext1, key1);

        original_success += original_ok;
        fast_success += fast_ok;
        checksum += ((uint64_t)original_ok << 1) ^ fast_ok ^ guessedBytes[0] ^ guessedBytes[13];
        if (fast_ok){
            checksum += plaintext1[0] + plaintext1[7] + plaintext1[15] + key1[0] + key1[17] + key1[31];
        }

        if (original_ok != fast_ok ||
            (original_ok && (memcmp(plaintext0, plaintext1, 16) != 0 || memcmp(key0, key1, 32) != 0))){
            mismatch++;
            printf("Mismatch at sample %llu\n", (unsigned long long)n);
            printf("guessedBytes:");
            for (int i = 0; i < 14; i++){
                printf(" %02x", guessedBytes[i]);
            }
            printf("\n");
            printf("original: %d, fast: %d\n", (int)original_ok, (int)fast_ok);
            if (original_ok && fast_ok){
                printf("plaintext original:");
                for (int i = 0; i < 16; i++){
                    printf(" %02x", plaintext0[i]);
                }
                printf("\nplaintext fast:    ");
                for (int i = 0; i < 16; i++){
                    printf(" %02x", plaintext1[i]);
                }
                printf("\nkey original:");
                for (int i = 0; i < 32; i++){
                    printf(" %02x", key0[i]);
                }
                printf("\nkey fast:    ");
                for (int i = 0; i < 32; i++){
                    printf(" %02x", key1[i]);
                }
                printf("\n");
            }
            break;
        }
    }

    bench_sink ^= checksum ^ original_success ^ (fast_success << 1) ^ mismatch;
    printf("GDprocessInboundFast reconstruct correctness check\n");
    printf("  samples:          %llu\n", (unsigned long long)iterations);
    printf("  original success: %llu\n", (unsigned long long)original_success);
    printf("  fast success:     %llu\n", (unsigned long long)fast_success);
    printf("  mismatch:         %llu\n", (unsigned long long)mismatch);
    printf("  checksum:         %llu\n", (unsigned long long)checksum);
    return mismatch == 0;
}

static bool checkGDMidFastVerify(uint64_t iterations){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t original_gd_success = 0;
    uint64_t mid_gd_success = 0;
    uint64_t original_aes_success = 0;
    uint64_t reference568_success = 0;
    uint64_t mid_aes_success = 0;
    uint64_t mismatch = 0;
    uint64_t ciphertext_checked = 0;
    uint64_t checksum = 0;

    for (uint64_t n = 0; n < iterations; n++){
        uint8_t guessedBytes[14];
        uint8_t plaintext[16], key[32], test_plaintext[16], ref_ciphertext[16];
        uint8_t x2[4][4], k2[4][4], k3[4][4], mid_ciphertext[4][4];
        uint8_t mid_ciphertext_no_check[4][4];

        for (int i = 0; i < 16; i += 8){
            rng_state = xorshift64star(rng_state);
            uint64_t random_bytes = rng_state;
            for (int j = 0; j < 8 && (i + j) < 14; j++){
                guessedBytes[i + j] = (random_bytes >> (8 * j)) & 0xFF;
            }
        }

        bool original_gd_ok = GDprocess(guessedBytes, plaintext, key);
        bool mid_gd_ok = GDprocessInboundFast(guessedBytes, NULL, NULL, x2, k2, k3);
        bool original_aes_ok = false;
        bool reference568_ok = false;
        bool mid_aes_ok = false;

        original_gd_success += original_gd_ok;
        mid_gd_success += mid_gd_ok;

        if (original_gd_ok){
            memcpy(test_plaintext, plaintext, 16);
            original_aes_ok = AES_256_12r(test_plaintext, key, true);
            original_aes_success += original_aes_ok;

            memcpy(ref_ciphertext, plaintext, 16);
            AES_256_12r(ref_ciphertext, key, false);
        }
        if (mid_gd_ok){
            mid_aes_ok = AES_256_12r_from_x2_k2_k3(x2, k2, k3, mid_ciphertext, true);
            reference568_ok = AES_256_12r_from_x2_k2_k3_check568_reference(x2, k2, k3);
            mid_aes_success += mid_aes_ok;
            reference568_success += reference568_ok;
            AES_256_12r_from_x2_k2_k3(x2, k2, k3, mid_ciphertext_no_check, false);
        }

        checksum += ((uint64_t)original_gd_ok << 1) ^ ((uint64_t)mid_gd_ok << 2) ^
                    ((uint64_t)original_aes_ok << 3) ^ ((uint64_t)reference568_ok << 4) ^
                    ((uint64_t)mid_aes_ok << 5) ^
                    guessedBytes[0] ^ guessedBytes[13];

        bool ciphertext_same = true;
        if (original_gd_ok && mid_gd_ok){
            ciphertext_checked++;
            for (int i = 0; i < 4; i++){
                for (int j = 0; j < 4; j++){
                    if (ref_ciphertext[4 * i + j] != mid_ciphertext_no_check[i][j]){
                        ciphertext_same = false;
                    }
                }
            }
            checksum += mid_ciphertext_no_check[0][0] + mid_ciphertext_no_check[1][3] +
                        mid_ciphertext_no_check[3][3] + ref_ciphertext[0] + ref_ciphertext[15];
        }

        if (original_gd_ok != mid_gd_ok || reference568_ok != mid_aes_ok || !ciphertext_same){
            mismatch++;
            printf("Mismatch at sample %llu\n", (unsigned long long)n);
            printf("guessedBytes:");
            for (int i = 0; i < 14; i++){
                printf(" %02x", guessedBytes[i]);
            }
            printf("\n");
            printf("original_gd: %d, mid_gd: %d\n", (int)original_gd_ok, (int)mid_gd_ok);
            printf("original_aes_56: %d, reference568: %d, mid_aes: %d\n",
                   (int)original_aes_ok, (int)reference568_ok, (int)mid_aes_ok);
            printf("ciphertext_same: %d\n", (int)ciphertext_same);
            break;
        }
    }

    bench_sink ^= checksum ^ original_gd_success ^ (mid_gd_success << 1) ^
                  (original_aes_success << 2) ^ (reference568_success << 3) ^
                  (mid_aes_success << 4) ^ mismatch;
    printf("x2/k2/k3 mid-state verification correctness check\n");
    printf("  samples:              %llu\n", (unsigned long long)iterations);
    printf("  original GD success:  %llu\n", (unsigned long long)original_gd_success);
    printf("  mid GD success:       %llu\n", (unsigned long long)mid_gd_success);
    printf("  original AES56 succ.: %llu\n", (unsigned long long)original_aes_success);
    printf("  reference568 success:%llu\n", (unsigned long long)reference568_success);
    printf("  mid AES568 success:  %llu\n", (unsigned long long)mid_aes_success);
    printf("  ciphertext checked:   %llu\n", (unsigned long long)ciphertext_checked);
    printf("  mismatch:             %llu\n", (unsigned long long)mismatch);
    printf("  checksum:             %llu\n", (unsigned long long)checksum);
    return mismatch == 0;
}

static void benchmarkUntilGDSuccessFastReconstruct(uint64_t target_success){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t attempts = 0;
    uint64_t gd_success = 0;

    auto begin = std::chrono::steady_clock::now();
    while (gd_success < target_success){
        gd_success += oneGDFastReconstruct(&rng_state, &checksum);
        attempts++;
    }
    auto end = std::chrono::steady_clock::now();

    double seconds = elapsedSeconds(begin, end);
    checksum ^= rng_state ^ attempts ^ (gd_success << 1);
    bench_sink ^= checksum;

    printf("GDprocessInboundFast reconstruct plaintext/key, no AES verification\n");
    printf("  target GD successes: %llu\n", (unsigned long long)target_success);
    printf("  total attempts:      %llu\n", (unsigned long long)attempts);
    printf("  seconds:             %.6f\n", seconds);
    printf("  ns/GD success:       %.3f\n", seconds * 1e9 / (double)gd_success);
    printf("  attempts/sec:        %.3f\n", (double)attempts / seconds);
    printf("  GD success/sec:      %.3f\n", (double)gd_success / seconds);
    printf("  attempts/GD success: %.6f\n", (double)attempts / (double)gd_success);
    printf("  checksum:            %llu\n", (unsigned long long)checksum);
}

static void benchmarkUntilGDSuccess(uint64_t target_success){
    uint64_t rng_state = 0x123456789abcdef0ULL;
    uint64_t checksum = 0;
    uint64_t attempts = 0;
    uint64_t gd_success = 0;
    uint64_t aes_success = 0;

    auto begin = std::chrono::steady_clock::now();
    while (gd_success < target_success){
        bool aes_ok = false;
        bool gd_ok = oneOriginalFlowCountGD(&rng_state, &checksum, &aes_ok);
        attempts++;
        if (gd_ok){
            gd_success++;
            aes_success += aes_ok;
        }
    }
    auto end = std::chrono::steady_clock::now();

    double seconds = elapsedSeconds(begin, end);
    checksum ^= rng_state ^ attempts ^ (gd_success << 1) ^ (aes_success << 2);
    bench_sink ^= checksum;

#if HAS_ARM_AESE
    printf("GDprocess successes + conditional AESE AES_256_12r(checkCondition=true)\n");
#else
    printf("GDprocess successes + conditional AES_256_12r(checkCondition=true)\n");
#endif
    printf("  target GD successes: %llu\n", (unsigned long long)target_success);
    printf("  total attempts:      %llu\n", (unsigned long long)attempts);
    printf("  seconds:             %.6f\n", seconds);
    printf("  ns/GD success:       %.3f\n", seconds * 1e9 / (double)gd_success);
    printf("  attempts/sec:        %.3f\n", (double)attempts / seconds);
    printf("  GD success/sec:      %.3f\n", (double)gd_success / seconds);
    printf("  attempts/GD success: %.6f\n", (double)attempts / (double)gd_success);
    printf("  AES accepted:        %llu\n", (unsigned long long)aes_success);
    printf("  checksum:            %llu\n", (unsigned long long)checksum);
}

#if HAS_ARM_AESE
static void expandRoundKeyBytes(const uint8_t key[32], uint8_t roundKey[13][16]){
    uint8_t keyBlock[7][32];

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

    for (int r = 0; r < 13; r++){
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                int word = 4 * r + j;
                roundKey[r][4 * j + i] = keyBlock[word / 8][8 * i + word % 8];
            }
        }
    }
}

static void packStateForAESE(const uint8_t in[16], uint8_t out[16]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            out[4 * j + i] = in[4 * i + j];
        }
    }
}

static void unpackStateFromAESE(const uint8_t in[16], uint8_t out[16]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            out[4 * i + j] = in[4 * j + i];
        }
    }
}

static uint32_t loadBe32(const uint8_t* x){
    return ((uint32_t)x[0] << 24) | ((uint32_t)x[1] << 16) |
           ((uint32_t)x[2] << 8) | (uint32_t)x[3];
}

static void storeBe32(uint8_t* out, uint32_t x){
    out[0] = (uint8_t)(x >> 24);
    out[1] = (uint8_t)(x >> 16);
    out[2] = (uint8_t)(x >> 8);
    out[3] = (uint8_t)x;
}

static uint32_t rotl32(uint32_t x, int n){
    return (x << n) | (x >> (32 - n));
}

static uint32_t subWordTable(uint32_t x){
    return ((uint32_t)sbox[(x >> 24) & 0xff] << 24) |
           ((uint32_t)sbox[(x >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(x >> 8) & 0xff] << 8) |
           (uint32_t)sbox[x & 0xff];
}

static void makeAESTables(uint32_t te0[256], uint32_t te1[256], uint32_t te2[256], uint32_t te3[256]){
    for (int x = 0; x < 256; x++){
        uint32_t y = sbox[x];
        uint32_t t = ((uint32_t)mul2(y) << 24) | ((uint32_t)y << 16) |
                     ((uint32_t)y << 8) | (uint32_t)mul3(y);
        te0[x] = t;
        te1[x] = rotl32(t, 24);
        te2[x] = rotl32(t, 16);
        te3[x] = rotl32(t, 8);
    }
}

static void expandRoundKeyWords(const uint8_t key[32], uint32_t roundKey[13][4]){
    uint8_t roundKeyBytes[13][16];
    expandRoundKeyBytes(key, roundKeyBytes);
    for (int r = 0; r < 13; r++){
        for (int c = 0; c < 4; c++){
            roundKey[r][c] = loadBe32(&roundKeyBytes[r][4 * c]);
        }
    }
}

NOINLINE static void AES_256_12r_table_packed_preexpanded(uint8_t stateBytes[16],
                                                          const uint32_t roundKey[13][4],
                                                          const uint32_t te0[256],
                                                          const uint32_t te1[256],
                                                          const uint32_t te2[256],
                                                          const uint32_t te3[256]){
    uint32_t s0 = loadBe32(&stateBytes[0]) ^ roundKey[0][0];
    uint32_t s1 = loadBe32(&stateBytes[4]) ^ roundKey[0][1];
    uint32_t s2 = loadBe32(&stateBytes[8]) ^ roundKey[0][2];
    uint32_t s3 = loadBe32(&stateBytes[12]) ^ roundKey[0][3];

    for (int r = 1; r < 12; r++){
        uint32_t t0 = te0[(s0 >> 24) & 0xff] ^ te1[(s1 >> 16) & 0xff] ^
                      te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ roundKey[r][0];
        uint32_t t1 = te0[(s1 >> 24) & 0xff] ^ te1[(s2 >> 16) & 0xff] ^
                      te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ roundKey[r][1];
        uint32_t t2 = te0[(s2 >> 24) & 0xff] ^ te1[(s3 >> 16) & 0xff] ^
                      te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ roundKey[r][2];
        uint32_t t3 = te0[(s3 >> 24) & 0xff] ^ te1[(s0 >> 16) & 0xff] ^
                      te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ roundKey[r][3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    uint32_t o0 = ((uint32_t)sbox[(s0 >> 24) & 0xff] << 24) ^
                  ((uint32_t)sbox[(s1 >> 16) & 0xff] << 16) ^
                  ((uint32_t)sbox[(s2 >> 8) & 0xff] << 8) ^
                  (uint32_t)sbox[s3 & 0xff] ^ roundKey[12][0];
    uint32_t o1 = ((uint32_t)sbox[(s1 >> 24) & 0xff] << 24) ^
                  ((uint32_t)sbox[(s2 >> 16) & 0xff] << 16) ^
                  ((uint32_t)sbox[(s3 >> 8) & 0xff] << 8) ^
                  (uint32_t)sbox[s0 & 0xff] ^ roundKey[12][1];
    uint32_t o2 = ((uint32_t)sbox[(s2 >> 24) & 0xff] << 24) ^
                  ((uint32_t)sbox[(s3 >> 16) & 0xff] << 16) ^
                  ((uint32_t)sbox[(s0 >> 8) & 0xff] << 8) ^
                  (uint32_t)sbox[s1 & 0xff] ^ roundKey[12][2];
    uint32_t o3 = ((uint32_t)sbox[(s3 >> 24) & 0xff] << 24) ^
                  ((uint32_t)sbox[(s0 >> 16) & 0xff] << 16) ^
                  ((uint32_t)sbox[(s1 >> 8) & 0xff] << 8) ^
                  (uint32_t)sbox[s2 & 0xff] ^ roundKey[12][3];

    storeBe32(&stateBytes[0], o0);
    storeBe32(&stateBytes[4], o1);
    storeBe32(&stateBytes[8], o2);
    storeBe32(&stateBytes[12], o3);
}

NOINLINE static void AES_256_12r_AESE_packed_preexpanded(uint8_t stateBytes[16], const uint8x16_t roundKey[13]){
    uint8x16_t state = vld1q_u8(stateBytes);

    for (int r = 0; r < 11; r++){
        state = vaesmcq_u8(vaeseq_u8(state, roundKey[r]));
    }
    state = vaeseq_u8(state, roundKey[11]);
    state = veorq_u8(state, roundKey[12]);

    vst1q_u8(stateBytes, state);
}

NOINLINE static void AES_256_12r_AESE_packed(uint8_t stateBytes[16], const uint8_t key[32]){
    uint8_t roundKeyBytes[13][16];
    uint8x16_t roundKey[13];
    expandRoundKeyBytes(key, roundKeyBytes);
    for (int r = 0; r < 13; r++){
        roundKey[r] = vld1q_u8(roundKeyBytes[r]);
    }
    AES_256_12r_AESE_packed_preexpanded(stateBytes, roundKey);
}

static bool checkAESEAddRoundKeyState(uint8x16_t state, uint8x16_t roundKey, int r){
    uint8_t ark[16];
    vst1q_u8(ark, veorq_u8(state, roundKey));

    if (r == 5 && !allowed34to7b(ark[0])){
        return false;
    }
    if (r == 6 && (!allowedDato34(ark[0]) || !allowedDato34(ark[4]) ||
                   !allowedDato34(ark[8]) || !allowedDato34(ark[12]))){
        return false;
    }

    return true;
}

NOINLINE static bool AES_256_12r_AESE_verify(uint8_t plaintext[16], const uint8_t key[32], bool checkCondition){
    uint8_t roundKeyBytes[13][16];
    uint8x16_t roundKey[13];
    uint8_t packed[16];

    expandRoundKeyBytes(key, roundKeyBytes);
    for (int r = 0; r < 13; r++){
        roundKey[r] = vld1q_u8(roundKeyBytes[r]);
    }

    packStateForAESE(plaintext, packed);
    uint8x16_t state = vld1q_u8(packed);

    for (int r = 0; r < 11; r++){
        if (checkCondition && !checkAESEAddRoundKeyState(state, roundKey[r], r)){
            return false;
        }
        state = vaesmcq_u8(vaeseq_u8(state, roundKey[r]));
    }

    if (checkCondition && !checkAESEAddRoundKeyState(state, roundKey[11], 11)){
        return false;
    }
    state = vaeseq_u8(state, roundKey[11]);
    state = veorq_u8(state, roundKey[12]);

    vst1q_u8(packed, state);
    unpackStateFromAESE(packed, plaintext);
    return true;
}

static bool selfTestAESE(){
    uint8_t plaintext0[16] = {
        0xef, 0x48, 0x90, 0xf5, 0x6a, 0xbd, 0x72, 0x63,
        0x4f, 0x31, 0x9e, 0xd9, 0x3e, 0x01, 0x0d, 0xbc
    };
    uint8_t plaintext1[16];
    uint8_t plaintext2[16];
    uint8_t key[32] = {
        0xef, 0x2e, 0x90, 0xf5, 0xe8, 0x17, 0x6b, 0x63,
        0x7e, 0x15, 0xaa, 0xd0, 0x31, 0x42, 0x0d, 0x9a,
        0xa5, 0xa5, 0x6c, 0xa3, 0x74, 0xf5, 0x46, 0x95,
        0x19, 0x10, 0xba, 0xbd, 0xfa, 0x6b, 0xa4, 0xe7
    };

    memcpy(plaintext1, plaintext0, 16);
    memcpy(plaintext2, plaintext0, 16);
    AES_256_12r(plaintext0, key, false);
    uint8_t packed_test[16];
    packStateForAESE(plaintext1, packed_test);
    AES_256_12r_AESE_packed(packed_test, key);
    uint8_t packed_ref[16];
    packStateForAESE(plaintext0, packed_ref);
    if (memcmp(packed_ref, packed_test, 16) != 0){
        return false;
    }

    if (!AES_256_12r_AESE_verify(plaintext2, key, false)){
        return false;
    }
    return memcmp(plaintext0, plaintext2, 16) == 0;
}

static void benchmarkAESE(uint64_t iterations){
    uint8_t plaintext[16] = {
        0xef, 0x48, 0x90, 0xf5, 0x6a, 0xbd, 0x72, 0x63,
        0x4f, 0x31, 0x9e, 0xd9, 0x3e, 0x01, 0x0d, 0xbc
    };
    uint8_t key[32] = {
        0xef, 0x2e, 0x90, 0xf5, 0xe8, 0x17, 0x6b, 0x63,
        0x7e, 0x15, 0xaa, 0xd0, 0x31, 0x42, 0x0d, 0x9a,
        0xa5, 0xa5, 0x6c, 0xa3, 0x74, 0xf5, 0x46, 0x95,
        0x19, 0x10, 0xba, 0xbd, 0xfa, 0x6b, 0xa4, 0xe7
    };
    uint8_t packedPlaintext[16];
    packStateForAESE(plaintext, packedPlaintext);
    uint64_t checksum = 0;

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        packedPlaintext[0] ^= (uint8_t)i;
        AES_256_12r_AESE_packed(packedPlaintext, key);
        checksum += packedPlaintext[0] ^ packedPlaintext[7] ^ packedPlaintext[15];
    }
    auto end = std::chrono::steady_clock::now();

    bench_sink ^= checksum;
    printRate("AESE AES_256_12r, expand key each call, packed state", iterations,
              elapsedSeconds(begin, end), checksum);
}

static void benchmarkAESEPreexpanded(uint64_t iterations){
    uint8_t plaintext[16] = {
        0xef, 0x48, 0x90, 0xf5, 0x6a, 0xbd, 0x72, 0x63,
        0x4f, 0x31, 0x9e, 0xd9, 0x3e, 0x01, 0x0d, 0xbc
    };
    uint8_t key[32] = {
        0xef, 0x2e, 0x90, 0xf5, 0xe8, 0x17, 0x6b, 0x63,
        0x7e, 0x15, 0xaa, 0xd0, 0x31, 0x42, 0x0d, 0x9a,
        0xa5, 0xa5, 0x6c, 0xa3, 0x74, 0xf5, 0x46, 0x95,
        0x19, 0x10, 0xba, 0xbd, 0xfa, 0x6b, 0xa4, 0xe7
    };
    uint8_t roundKeyBytes[13][16];
    uint8x16_t roundKey[13];
    uint8_t packedPlaintext[16];
    uint64_t checksum = 0;

    expandRoundKeyBytes(key, roundKeyBytes);
    for (int r = 0; r < 13; r++){
        roundKey[r] = vld1q_u8(roundKeyBytes[r]);
    }
    packStateForAESE(plaintext, packedPlaintext);

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        packedPlaintext[0] ^= (uint8_t)i;
        AES_256_12r_AESE_packed_preexpanded(packedPlaintext, roundKey);
        checksum += packedPlaintext[0] ^ packedPlaintext[7] ^ packedPlaintext[15];
    }
    auto end = std::chrono::steady_clock::now();

    bench_sink ^= checksum;
    printRate("AESE AES_256_12r, preexpanded key, packed state", iterations,
              elapsedSeconds(begin, end), checksum);
}

static bool selfTestTableAES(){
    uint8_t plaintext0[16] = {
        0xef, 0x48, 0x90, 0xf5, 0x6a, 0xbd, 0x72, 0x63,
        0x4f, 0x31, 0x9e, 0xd9, 0x3e, 0x01, 0x0d, 0xbc
    };
    uint8_t plaintext1[16];
    uint8_t key[32] = {
        0xef, 0x2e, 0x90, 0xf5, 0xe8, 0x17, 0x6b, 0x63,
        0x7e, 0x15, 0xaa, 0xd0, 0x31, 0x42, 0x0d, 0x9a,
        0xa5, 0xa5, 0x6c, 0xa3, 0x74, 0xf5, 0x46, 0x95,
        0x19, 0x10, 0xba, 0xbd, 0xfa, 0x6b, 0xa4, 0xe7
    };
    uint32_t roundKey[13][4];
    uint32_t te0[256], te1[256], te2[256], te3[256];
    uint8_t packed_test[16];
    uint8_t packed_ref[16];

    memcpy(plaintext1, plaintext0, 16);
    AES_256_12r(plaintext0, key, false);
    packStateForAESE(plaintext1, packed_test);
    packStateForAESE(plaintext0, packed_ref);
    expandRoundKeyWords(key, roundKey);
    makeAESTables(te0, te1, te2, te3);
    AES_256_12r_table_packed_preexpanded(packed_test, roundKey, te0, te1, te2, te3);

    return memcmp(packed_ref, packed_test, 16) == 0;
}

static void benchmarkTablePreexpanded(uint64_t iterations){
    uint8_t plaintext[16] = {
        0xef, 0x48, 0x90, 0xf5, 0x6a, 0xbd, 0x72, 0x63,
        0x4f, 0x31, 0x9e, 0xd9, 0x3e, 0x01, 0x0d, 0xbc
    };
    uint8_t key[32] = {
        0xef, 0x2e, 0x90, 0xf5, 0xe8, 0x17, 0x6b, 0x63,
        0x7e, 0x15, 0xaa, 0xd0, 0x31, 0x42, 0x0d, 0x9a,
        0xa5, 0xa5, 0x6c, 0xa3, 0x74, 0xf5, 0x46, 0x95,
        0x19, 0x10, 0xba, 0xbd, 0xfa, 0x6b, 0xa4, 0xe7
    };
    uint32_t roundKey[13][4];
    uint32_t te0[256], te1[256], te2[256], te3[256];
    uint8_t packedPlaintext[16];
    uint64_t checksum = 0;

    expandRoundKeyWords(key, roundKey);
    makeAESTables(te0, te1, te2, te3);
    packStateForAESE(plaintext, packedPlaintext);

    auto begin = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iterations; i++){
        packedPlaintext[0] ^= (uint8_t)i;
        AES_256_12r_table_packed_preexpanded(packedPlaintext, roundKey, te0, te1, te2, te3);
        checksum += packedPlaintext[0] ^ packedPlaintext[7] ^ packedPlaintext[15];
    }
    auto end = std::chrono::steady_clock::now();

    bench_sink ^= checksum;
    printRate("T-table AES_256_12r, preexpanded key, packed state", iterations,
              elapsedSeconds(begin, end), checksum);
}
#endif

int main(int argc, char** argv){
    uint64_t iterations = 1000000000ULL;
    bool gd_success_mode = false;
    bool gd_original_fixed_mode = false;
    bool gd_original_success_mode = false;
    bool gd_only_success_mode = false;
    bool gd_fast_success_mode = false;
    bool gd_fast_check_mode = false;
    bool gd_fast_reconstruct_success_mode = false;
    bool gd_fast_reconstruct_check_mode = false;
    bool gd_mid_only_fixed_mode = false;
    bool gd_mid_fixed_mode = false;
    bool gd_mid_success_mode = false;
    bool gd_mid_check_mode = false;
    if (argc >= 2 && strcmp(argv[1], "gd-success") == 0){
        gd_success_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-original-fixed") == 0){
        gd_original_fixed_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-original-success") == 0){
        gd_original_success_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-only-success") == 0){
        gd_only_success_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-fast-success") == 0){
        gd_fast_success_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-fast-reconstruct-success") == 0){
        gd_fast_reconstruct_success_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-fast-reconstruct-check") == 0){
        gd_fast_reconstruct_check_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-mid-fixed") == 0){
        gd_mid_fixed_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-mid-success") == 0){
        gd_mid_success_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-mid-only-fixed") == 0){
        gd_mid_only_fixed_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-mid-check") == 0){
        gd_mid_check_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2 && strcmp(argv[1], "gd-fast-check") == 0){
        gd_fast_check_mode = true;
        if (argc >= 3){
            iterations = strtoull(argv[2], NULL, 10);
        }
    }
    else if (argc >= 2){
        iterations = strtoull(argv[1], NULL, 10);
    }

    if (gd_success_mode || gd_original_success_mode || gd_only_success_mode || gd_fast_success_mode ||
        gd_fast_reconstruct_success_mode || gd_mid_success_mode){
        printf("target GD successes = %llu\n", (unsigned long long)iterations);
    }
    else if (gd_fast_check_mode || gd_fast_reconstruct_check_mode || gd_mid_check_mode){
        printf("check samples = %llu\n", (unsigned long long)iterations);
    }
    else{
        printf("iterations = %llu\n", (unsigned long long)iterations);
    }

    auto table_begin = std::chrono::steady_clock::now();
    MakeTable();
    auto table_end = std::chrono::steady_clock::now();
    printf("LookupTable generated in %.6f seconds.\n", elapsedSeconds(table_begin, table_end));

    if (gd_success_mode){
        benchmarkUntilGDSuccess(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_original_fixed_mode){
        benchmarkGDAndOriginalAES(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_original_success_mode){
        benchmarkUntilGDSuccessOriginalAES(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_only_success_mode){
        benchmarkUntilGDSuccessOnly(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_fast_success_mode){
        benchmarkUntilGDSuccessFast(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_fast_reconstruct_success_mode){
        benchmarkUntilGDSuccessFastReconstruct(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_mid_only_fixed_mode){
        benchmarkGDMidOnly(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_mid_fixed_mode){
        benchmarkGDMidFastVerify(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_mid_success_mode){
        benchmarkUntilGDSuccessMidFastVerify(iterations);
        return (int)(bench_sink & 0);
    }
    if (gd_fast_check_mode){
        bool ok = checkGDInboundFast(iterations);
        return ok ? (int)(bench_sink & 0) : 1;
    }
    if (gd_fast_reconstruct_check_mode){
        bool ok = checkGDFastReconstruct(iterations);
        return ok ? (int)(bench_sink & 0) : 1;
    }
    if (gd_mid_check_mode){
        bool ok = checkGDMidFastVerify(iterations);
        return ok ? (int)(bench_sink & 0) : 1;
    }

    benchmarkGDAndMaybeAES(iterations);

#if HAS_ARM_AESE
    if (!selfTestAESE()){
        printf("AESE self-test failed; skip AESE benchmark.\n");
        return 1;
    }
    if (!selfTestTableAES()){
        printf("T-table AES self-test failed; skip T-table benchmark.\n");
        return 1;
    }
    benchmarkAESE(iterations);
    benchmarkAESEPreexpanded(iterations);
    benchmarkTablePreexpanded(iterations);
#else
    printf("AESE benchmark skipped: this build target does not expose ARM AESE intrinsics.\n");
    printf("On ARMv8, compile with crypto enabled, for example: clang++ -O3 -std=c++17 -march=armv8-a+crypto AES_12_256_bench.c++ -o aes_12_256_bench\n");
#endif

    return (int)(bench_sink & 0);
}
