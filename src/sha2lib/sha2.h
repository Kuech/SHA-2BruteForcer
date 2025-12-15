#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

struct message_block
{
    uint length;
    uint8_t* block;
};

class Sha2
{
protected:
    enum WordIndex {la,lb,lc,ld,le,lf,lg,lh};
    virtual void build_msg_block(const std::string input, message_block* msg) = 0;
    virtual void pre_process_step(const uint8_t* chunk, uint32_t* chunk_32bit_entry) = 0;
    virtual void hash_sha256(const uint32_t* input)= 0;
    message_block msg_block;
    virtual bool equals(const Sha2& other) const = 0;
public:
    friend bool operator==(const Sha2& lhs, const Sha2& rhs);
    virtual ~Sha2();
    std::string ToString();
    virtual std::array<uint32_t, 8> GetWord() const = 0;
};
class Sha256 : public Sha2
{
protected:
    bool equals(const Sha2& other) const override;
public:
    void build_msg_block(const std::string input, message_block* msg) override;
    void pre_process_step(const uint8_t* chunk, uint32_t chunk_32bit_entry[64]) override;
    void hash_sha256(const uint32_t* input) override;
    std::array<uint32_t, 8> GetWord() const override;
    Sha256(const std::string message);
    Sha256(const uint32_t _sha256_32bit_entry[8]);
private:
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
};
