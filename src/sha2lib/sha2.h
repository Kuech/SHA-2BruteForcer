#include <cstdint>

#define ROTATE(i, r) ((i >> r) | (i << (32 - r)))

uint8_t* hash_sha256(uint32_t* input);
