#include <cstdint>

#define ROTATE(r, i) ((i >> r) | (i << (32 - r)))

uint8_t* hash_sha256(uint8_t* input);
