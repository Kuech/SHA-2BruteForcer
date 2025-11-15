#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

struct message_block
{
    uint length;
    uint8_t* block;
};

class Sha256
{
private:
    void build_msg_block(const std::string input, message_block* msg);
    void pre_process_step(const uint8_t* chunk, uint32_t chunk_32bit_entry[64]);
    void hash_sha256(const uint32_t* input, uint32_t sha256_32bit_entry[8]);
    message_block msg_block;
public:
    uint32_t sha256_32bit_entry[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
    };
    Sha256(const std::string message);
    Sha256(const uint32_t _sha256_32bit_entry[8]);
    ~Sha256();
    bool operator==(const Sha256 hashedMessage);
};
