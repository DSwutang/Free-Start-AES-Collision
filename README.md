# Free-Start Collision Attack on AES-256

This repository contains search, benchmarking, and verification code for a partial implementation of the free-start collision attack on 12-round AES-256. The message pair follows the differential characteristic up to the input of the round-10 S-boxes.

## Files

```text
.
├── AES_12_256.c++              # CPU search
├── AES_12_256_gpu.cu           # CUDA search
├── AES_12_256_bench.c++        # GD and AES performance comparison
└── AES_12_256_found_trace.c++  # Round-by-round verification of the message pair
```

## Compilation

Run the following commands from this directory:

```bash
g++ AES_12_256.c++ -O3 -std=c++17 -o aes_12_256
g++ AES_12_256_bench.c++ -O3 -std=c++17 -o aes_12_256_bench
g++ AES_12_256_found_trace.c++ -O3 -std=c++17 -o aes_12_256_found_trace
```

Compile the GPU search with the CUDA toolkit (requires an NVIDIA GPU):

```bash
nvcc AES_12_256_gpu.cu -O3 -arch=sm_70 -std=c++17 -o aes_12_256_gpu
```

Adjust `-arch` to match the target GPU. Run each executable with `./<executable>`; no command-line arguments are required. The benchmark compares 10 million GD successes, including conditional verification, with 10 million AES encryptions using preexpanded keys. Its T-table and AESE tests require a build target exposing ARM crypto intrinsics.

## Results

The partial attack has expected time complexity $O(2^{42})$. The values below define the message pair found in 67 minutes on an NVIDIA V100 GPU and embedded in `AES_12_256_found_trace.c++`.

All three values contain 16 bytes in the source's row-major layout. Here, `P` is the base AES plaintext, and `K0` and `K1` are the two halves of the 256-bit AES key, `K = K0 || K1`.

```text
P:  2c 24 51 f8 dc 9f 1d 4c 07 0e 45 30 3a f2 25 96
K0: 2c 42 51 f8 5e 35 04 4c 36 2a 71 39 35 b1 25 b0
K1: a5 60 6c a3 ed f5 85 eb d8 bb ba f0 b1 04 0c e7
```

## Verification

```bash
./aes_12_256_found_trace
```

The program derives the paired plaintext and key using the fixed differences in the source and prints the round-by-round state differences. At the input of the round-10 S-boxes, the difference matches the expected characteristic:

```text
round 10 after AddRoundKey
diff:
da da 00 00
00 00 00 00
00 00 00 00
00 00 00 00
```
