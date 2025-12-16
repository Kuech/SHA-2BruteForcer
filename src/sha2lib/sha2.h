#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

class Sha2
{
protected:
    enum WordIndex {la,lb,lc,ld,le,lf,lg,lh};
    std::vector<uint8_t> build_msg_block(const std::string input);
    virtual std::array<uint32_t, 64> pre_process_step(const uint8_t* chunk) = 0;
    virtual void hash_sha256(const std::array<uint32_t, 64> input)= 0;
    virtual bool equals(const Sha2& other) const = 0;
    std::vector<uint8_t> block;
    size_t round;
public:
    friend bool operator==(const Sha2& lhs, const Sha2& rhs);
    ~Sha2();
    Sha2();
    Sha2(const std::string message);
    std::string ToString();
    virtual std::array<uint32_t, 8> GetWord() const = 0;
};
class Sha256 : public Sha2
{
protected:
    bool equals(const Sha2& other) const override;
    std::array<uint32_t, 64> pre_process_step(const uint8_t* chunk) override;
    void hash_sha256(const std::array<uint32_t, 64> input) override;
public:
    std::array<uint32_t, 8> GetWord() const override;
    Sha256(const std::string message);
    Sha256(const uint32_t _sha256_32bit_entry[8]);
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
