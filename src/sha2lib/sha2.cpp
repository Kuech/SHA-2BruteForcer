#include "sha2.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <array>
#include <sstream>
#include <string>

#define ROTATE(i, r) ((i >> r) | (i << (32 - r)))
// Check out https://sha256algorithm.com/
using namespace std;

const static uint32_t k[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 
};

Sha2::Sha2(const std::string message)
{
    this->block = this->build_msg_block(message);
    this->round = this->block.size()/64;
}

Sha256::Sha256(const std::string message) : Sha2(message)
{
    for(uint i=0;i<this->round;i++)
    {
        auto pre_proc_msg = this->pre_process_step(&this->block.data()[i*64]);
        this->hash_sha256(pre_proc_msg);
    }
}

Sha256::Sha256(const uint32_t _sha256_32bit_entry[8]) : Sha2()
{
    copy(_sha256_32bit_entry,_sha256_32bit_entry+8,this->word_entry);
}

Sha2::Sha2()
{
}

Sha2::~Sha2()
{
}

bool operator==(const Sha2& lhs, const Sha2& rhs)
{
    if(typeid(lhs) != typeid(rhs))
    {
        return false;
    }
    return lhs.equals(rhs);
}

bool Sha256::equals(const Sha2& other) const
{
    auto _other = dynamic_cast<const Sha256*>(&other);
    auto otherValue = _other->GetWord();
    auto thisValue = this->GetWord();
    for(int i=0;i<8;i++)
    {
        if(thisValue[i] != otherValue[i])
        {
            return false;
        }
    }
    return true;
}

std::array<uint32_t, 8> Sha256::GetWord() const
{
    std::array<uint32_t, 8> value
    {
        this->word_entry[la],
        this->word_entry[lb],
        this->word_entry[lc],
        this->word_entry[ld],
        this->word_entry[le],
        this->word_entry[lf],
        this->word_entry[lg],
        this->word_entry[lh],
    };
    return value;
}

void Sha256::hash_sha256(const std::array<uint32_t, 64> input)
{
    uint32_t wordCopy[8];
    copy(this->word_entry, this->word_entry+8, wordCopy);

    for(int i=0;i<64;i++)
    {
        uint32_t S1 = (ROTATE(wordCopy[le], 6) ^ ROTATE(wordCopy[le], 11) ^ ROTATE(wordCopy[le], 25));
        uint32_t ch = (wordCopy[le] & wordCopy[lf]) ^ ((~wordCopy[le]) & wordCopy[lg]);
        uint32_t temp1 = wordCopy[lh] + S1 + ch + k[i] + input[i];
        uint32_t S0 = (ROTATE(wordCopy[la], 2) ^ ROTATE(wordCopy[la], 13) ^ ROTATE(wordCopy[la], 22));
        uint32_t maj = (wordCopy[la] & wordCopy[lb]) ^ (wordCopy[la] & wordCopy[lc]) ^ (wordCopy[lb] & wordCopy[lc]);
        uint32_t temp2 = S0 + maj;

        wordCopy[lh] = wordCopy[lg];
        wordCopy[lg] = wordCopy[lf];
        wordCopy[lf] = wordCopy[le];
        wordCopy[le] = wordCopy[ld] + temp1;
        wordCopy[ld] = wordCopy[lc];
        wordCopy[lc] = wordCopy[lb];
        wordCopy[lb] = wordCopy[la];
        wordCopy[la] = temp1 + temp2;
    }

    this->word_entry[la] += wordCopy[la];
    this->word_entry[lb] += wordCopy[lb];
    this->word_entry[lc] += wordCopy[lc];
    this->word_entry[ld] += wordCopy[ld];
    this->word_entry[le] += wordCopy[le];
    this->word_entry[lf] += wordCopy[lf];
    this->word_entry[lg] += wordCopy[lg];
    this->word_entry[lh] += wordCopy[lh];
}

std::array<uint32_t, 64> Sha256::pre_process_step(const uint8_t* chunk)
{
    std::array<uint32_t, 64> pre_proc_msg;
    fill(pre_proc_msg.begin(), pre_proc_msg.end(), 0);

    for(int i=0;i<64;i++)
    {
        // Yeah I know it's ugly, but if you know bitwise operations, it makes sense...
        pre_proc_msg[i/4] = (chunk[i] << (24 - ((i%4) * 8))) | pre_proc_msg[i/4];
    }

    for(int i=16;i<64;i++)
    {
        uint32_t s0 = (ROTATE(pre_proc_msg[i-15], 7) ^ ROTATE(pre_proc_msg[i-15], 18) ^ (pre_proc_msg[i-15] >> 3));
        uint32_t s1 = (ROTATE(pre_proc_msg[i-2], 17) ^ ROTATE(pre_proc_msg[i-2], 19) ^ (pre_proc_msg[i-2] >> 10));
        pre_proc_msg[i] = pre_proc_msg[i-16] + s0 + pre_proc_msg[i-7] + s1;
    }

    return pre_proc_msg;
}

std::vector<uint8_t> Sha2::build_msg_block(const string input)
{
    std::vector<uint8_t> msg;
    const uint remaining_bits= 64-((input.length()+1+8)%64);
    size_t length = (input.length()+1+8)+remaining_bits;
    msg.resize(length);

    fill(msg.begin(), msg.end(), 0);
    memcpy(msg.data(),input.data(),input.length() * sizeof(uint8_t));

    msg.at(input.length()) = 0b10000000;

    uint64_t stringlengthInBit =input.length() * 8;
    for(size_t i=0;i<8;i++)
    {
        msg.at(msg.size() - 8 + i) = stringlengthInBit >> (56  - 8 * i) & 0xFF;
    }
    return msg;
}

std::string Sha2::ToString()
{
    std::ostringstream oss;
    auto buf = this->GetWord();
    for(size_t i=0;i<buf.size();i++)
    {
        oss << std::uppercase << std::hex << buf[i];
    }
    return oss.str();
}


void testSha256Hash(const string inputString, const uint32_t* expectedSha2Hash)
{
    Sha256 hashedString = Sha256(inputString);
    Sha256 expectedSha256 = Sha256(expectedSha2Hash);

    string testResult;
    if(hashedString == expectedSha256)
    {
        testResult = "✅";
    }
    else
    {
        testResult = "❌";
    }

    cout << "================================================================================================\n";
    cout << "Test for \"" << inputString << "\" " << testResult << '\n';
    cout << "Expected hash =>\n";
    cout << expectedSha256.ToString() << endl;
    cout << "Actual hash =>\n";
    cout << hashedString.ToString() << endl;
    cout << "================================================================================================\n\n";
}

int main() {
    static const string testString = "aaa";
    // 64‑hex‑digit literal → 32 bytes
    static const uint32_t data[8] = {
        0x9834876d,
        0xcfb05cb1,
        0x67a5c249,
        0x53eba58c,
        0x4ac89b1a,
        0xdf57f28f,
        0x2f9d09af,
        0x107ee8f0
    };

    static const string testString2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const uint32_t data2[8] = {
        0xb35439a4,
        0xac6f0948,
        0xb6d6f9e3,
        0xc6af0f5f,
        0x590ce20f,
        0x1bde7090,
        0xef797068,
        0x6ec6738a
    };
    testSha256Hash(testString, data);
    testSha256Hash(testString2, data2);
}
