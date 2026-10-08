#include <cstdio>
#include <cstdint>
#include <cstring>

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

#define mul2(x) ((((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b)) & 0xFF)
#define mul3(x) (mul2(x) ^ (x))

static void printMatrix(const char* name, const uint8_t state[4][4]){
    printf("%s:\n", name);
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            printf("%02x ", state[i][j]);
        }
        printf("\n");
    }
}

static void printDiff(const char* name, const uint8_t state0[4][4], const uint8_t state1[4][4]){
    uint8_t diff[4][4];
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            diff[i][j] = state0[i][j] ^ state1[i][j];
        }
    }
    printf("\n%s\n", name);
    printMatrix("diff", diff);
}

static void bytesToState(const uint8_t in[16], uint8_t state[4][4]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = in[i * 4 + j];
        }
    }
}

static void stateToBytes(const uint8_t state[4][4], uint8_t out[16]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            out[i * 4 + j] = state[i][j];
        }
    }
}

static void addRoundKey(uint8_t state[4][4], const uint8_t roundKey[4][4]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] ^= roundKey[i][j];
        }
    }
}

static void subBytes(uint8_t state[4][4]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = sbox[state[i][j]];
        }
    }
}

static void shiftRows(uint8_t state[4][4]){
    uint8_t temp;
    temp = state[1][0];
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
}

static void mixColumns(uint8_t state[4][4]){
    uint8_t tstate[4];
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

static void expandRoundKey(const uint8_t key[32], uint8_t roundKey[13][4][4]){
    uint8_t keyBlock[7][32];
    for (int i = 0; i < 4; i ++){
        for (int j = 0; j < 4; j ++){
            keyBlock[0][8*i+j] = key[4*i+j];
            keyBlock[0][8*i+4+j] = key[16+4*i+j];
        }
    }
    for (int i = 1; i < 7; i ++){
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
    for (int r = 0; r < 13; r ++){
        for (int i = 0; i < 4; i ++){
            for (int j = 0; j < 4; j ++){
                roundKey[r][i][j] = keyBlock[(4*r+j)/8][8*i+(4*r+j)%8];
            }
        }
    }
}

static void AES_verify(const uint8_t plaintext0[16], const uint8_t key0[32],
                       const uint8_t plaintext1[16], const uint8_t key1[32]){
    uint8_t roundKey0[13][4][4];
    uint8_t roundKey1[13][4][4];
    uint8_t state0[4][4];
    uint8_t state1[4][4];
    expandRoundKey(key0, roundKey0);
    expandRoundKey(key1, roundKey1);
    bytesToState(plaintext0, state0);
    bytesToState(plaintext1, state1);
    printDiff("plaintext", state0, state1);
    printDiff("roundKey[6]", roundKey0[6], roundKey1[6]);
    printDiff("roundKey[7]", roundKey0[7], roundKey1[7]);
    printDiff("roundKey[8]", roundKey0[8], roundKey1[8]);
    for (int r = 0; r < 12; r++){
        char label[64];
        addRoundKey(state0, roundKey0[r]);
        addRoundKey(state1, roundKey1[r]);
        snprintf(label, sizeof(label), "round %d after AddRoundKey", r);
        printDiff(label, state0, state1);
        subBytes(state0);
        subBytes(state1);
        shiftRows(state0);
        shiftRows(state1);
        if (r != 11){
            mixColumns(state0);
            mixColumns(state1);
        }
    }
    addRoundKey(state0, roundKey0[12]);
    addRoundKey(state1, roundKey1[12]);
    printDiff("ciphertext after final AddRoundKey", state0, state1);
    uint8_t out0[16], out1[16];
    stateToBytes(state0, out0);
    stateToBytes(state1, out1);
    printf("\nciphertext diff bytes: ");
    for (int i = 0; i < 16; i++){
        printf("%02x ", out0[i] ^ out1[i]);
    }
    printf("\n");
}

static void randomTest(){
    uint8_t x0[16] = {
        0x00, 0x66, 0x00, 0x00,
        0x82, 0xaa, 0x19, 0x00,
        0x31, 0x24, 0x34, 0x09,
        0x0f, 0x43, 0x00, 0x26
    };
    uint8_t key0[32] = {
        0x2c, 0x42, 0x51, 0xf8,
        0x5e, 0x35, 0x04, 0x4c,
        0x36, 0x2a, 0x71, 0x39,
        0x35, 0xb1, 0x25, 0xb0,
        0xa5, 0x60, 0x6c, 0xa3,
        0xed, 0xf5, 0x85, 0xeb,
        0xd8, 0xbb, 0xba, 0xf0,
        0xb1, 0x04, 0x0c, 0xe7
    };
    uint8_t keyDiff[32] = {
        0x2c, 0xf6, 0x2c, 0xf6,
        0x7b, 0x7b, 0x7b, 0x7b,
        0x7b, 0x7b, 0x7b, 0x7b,
        0x8d, 0x8d, 0x8d, 0x8d,
        0x5c, 0x00, 0x5c, 0x00,
        0x34, 0x00, 0x34, 0x00,
        0x34, 0x00, 0x34, 0x00,
        0x5c, 0x00, 0x5c, 0x00
    };
    uint8_t plaintext0[16];
    uint8_t plaintext1[16];
    uint8_t key1[32];
    for (int i = 0; i < 16; i++){
        plaintext0[i] = key0[i] ^ x0[i];
    }
    memcpy(plaintext1, plaintext0, 16);
    memcpy(key1, key0, 32);
    plaintext1[0] ^= 0xda;
    for (int i = 0; i < 32; i++){
        key1[i] ^= keyDiff[i];
    }
    AES_verify(plaintext0, key0, plaintext1, key1);
}

int main(){
    randomTest();
    return 0;
}
