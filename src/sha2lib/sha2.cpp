#include "sha2.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <array>
#include <sstream>
#include <string>

#define RIGHT_ROTATE(i, r) ((i >> r) | (i << (32 - r)))
#define s0(i) (RIGHT_ROTATE(i, 7) ^ RIGHT_ROTATE(i, 18) ^ (i >> 3))
#define s1(i) (RIGHT_ROTATE(i, 17) ^ RIGHT_ROTATE(i, 19) ^ (i >> 10))
#define S0(a) (RIGHT_ROTATE(a, 2) ^ RIGHT_ROTATE(a, 13) ^ RIGHT_ROTATE(a, 22))
#define S1(e) (RIGHT_ROTATE(e, 6) ^ RIGHT_ROTATE(e, 11) ^ RIGHT_ROTATE(e, 25))
#define CH(e,f,g) ((e & f) ^ ((~e) & g))
#define MAJ(a,b,c) ((a & b) ^ (a & c) ^ (b & c))
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

template<typename WordBitSize, size_t ChunkSize>
Sha2Base<WordBitSize, ChunkSize>::Sha2Base(const std::string message)
{
    this->block = this->build_msg_block(message);
}

Sha256Digest::Sha256Digest(const std::string message) : Sha2Base(message)
{
    while(this->block.size() > 0)
    {
        auto pre_proc_msg = this->pre_process_chunk(&this->block.data()[0]);
        this->hash(pre_proc_msg);
        this->block.erase(this->block.begin(), this->block.begin()+64);
    }
}

Sha256Digest::Sha256Digest(const uint32_t _sha256_32bit_entry[8]) : Sha2Base()
{
    copy(_sha256_32bit_entry,_sha256_32bit_entry+8,this->word_entry);
}

template<typename WordBitSize, size_t ChunkSize>
Sha2Base<WordBitSize, ChunkSize>::Sha2Base()
{
}

template<typename WordBitSize, size_t ChunkSize>
Sha2Base<WordBitSize, ChunkSize>::~Sha2Base()
{
}

template<typename WordBitSize, size_t ChunkSize>
std::array<WordBitSize, 8> Sha2Base<WordBitSize, ChunkSize>::GetWord() const
{
    std::array<WordBitSize, 8> value
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

template<typename WordBitSize, size_t ChunkSize>
void Sha2Base<WordBitSize, ChunkSize>::hash(const std::array<WordBitSize, ChunkSize> input)
{
    WordBitSize wordCopy[8];
    copy(this->word_entry, this->word_entry+8, wordCopy);

    for(size_t i=0;i<ChunkSize;i++)
    {
        WordBitSize temp1 = wordCopy[lh] + S1(wordCopy[le]) + CH(wordCopy[le],wordCopy[lf],wordCopy[lg]) + k[i] + input[i];
        WordBitSize temp2 = S0(wordCopy[la]) + MAJ(wordCopy[la], wordCopy[lb], wordCopy[lc]);

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

template<typename WordBitSize, size_t ChunkSize>
std::array<WordBitSize, ChunkSize> Sha2Base<WordBitSize, ChunkSize>::pre_process_chunk(const uint8_t* chunk)
{
    std::array<WordBitSize, ChunkSize> pre_proc_msg;
    fill(pre_proc_msg.begin(), pre_proc_msg.end(), 0);

    for(size_t i=0;i<ChunkSize;i++)
    {
        // Yeah I know it's ugly, but if you know bitwise operations, it makes sense...
        // Anyway, I am adding 8 bit data into 32 bit data,
        // so 4 data of 8 bit must fit into a single 32 bit data
        pre_proc_msg[i/4] = (chunk[i] << (24 - ((i%4) * 8))) | pre_proc_msg[i/4];
    }

    for(size_t i=16;i<ChunkSize;i++)
    {
        pre_proc_msg[i] = pre_proc_msg[i-16] + s0(pre_proc_msg[i-15]) + pre_proc_msg[i-7] + s1(pre_proc_msg[i-2]);
    }

    return pre_proc_msg;
}

template<typename WordBitSize, size_t ChunkSize>
std::vector<uint8_t> Sha2Base<WordBitSize, ChunkSize>::build_msg_block(const string input)
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

template<typename WordBitSize, size_t ChunkSize>
std::string Sha2Base<WordBitSize, ChunkSize>::ToString()
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
    Sha256Digest hashedString = Sha256Digest(inputString);
    Sha256Digest expectedSha256 = Sha256Digest(expectedSha2Hash);

    string testResult;
    if(hashedString.GetWord() == expectedSha256.GetWord())
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
