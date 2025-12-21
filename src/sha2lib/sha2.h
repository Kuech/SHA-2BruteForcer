#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

class Sha2Base
{
protected:
    enum WordIndex {la,lb,lc,ld,le,lf,lg,lh};
    std::vector<uint8_t> build_msg_block(const std::string input);
    virtual std::array<uint32_t, 64> pre_process_chunk(const uint8_t* chunk) = 0;
    virtual void hash(const std::array<uint32_t, 64> input)= 0;
    virtual bool equals(const Sha2Base& other) const = 0;
    std::vector<uint8_t> block;
public:
    friend bool operator==(const Sha2Base& lhs, const Sha2Base& rhs);
    ~Sha2Base();
    Sha2Base();
    Sha2Base(const std::string message);
    std::string ToString();
    virtual std::array<uint32_t, 8> GetWord() const = 0;
};
class Sha256Digest : public Sha2Base
{
protected:
    bool equals(const Sha2Base& other) const override;
    std::array<uint32_t, 64> pre_process_chunk(const uint8_t* chunk) override;
    void hash(const std::array<uint32_t, 64> input) override;
public:
    std::array<uint32_t, 8> GetWord() const override;
    Sha256Digest(const std::string message);
    Sha256Digest(const uint32_t _sha256_32bit_entry[8]);
private:
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
};
