#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

template<typename WordBitSize, size_t ChunkSize>
class Sha2Base
{
protected:
    enum WordIndex {la,lb,lc,ld,le,lf,lg,lh};
    std::vector<uint8_t> build_msg_block(const std::string input);
    std::array<WordBitSize, ChunkSize> pre_process_chunk(const uint8_t* chunk);
    void hash(const std::array<WordBitSize, ChunkSize> input);
    std::vector<uint8_t> block;
    uint32_t word_entry[8]
    {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
    };
public:
    ~Sha2Base();
    Sha2Base();
    Sha2Base(const std::string message);
    std::string ToString();
    std::array<WordBitSize, 8> GetWord() const;
};
class Sha256Digest : public Sha2Base<uint32_t, 64>
{
public:
    Sha256Digest(const std::string message);
    Sha256Digest(const uint32_t _sha256_32bit_entry[8]);
};
