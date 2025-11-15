#include "sha2.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>

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

Sha256::Sha256(const std::string message)
{
    this->build_msg_block(message, &this->msg_block);
    uint round = this->msg_block.length/64;
    for(uint i=0;i<round;i++)
    {
        uint32_t pre_proc_msg[64];
        memset(pre_proc_msg, 0, 64*sizeof(uint32_t));
        this->pre_process_step(&this->msg_block.block[i*64], &pre_proc_msg[0]);
        this->hash_sha256(pre_proc_msg, &this->sha256_32bit_entry[0]);
    }
}

Sha256::Sha256(const uint32_t _sha256_32bit_entry[8]) : Sha2()
{
    copy(_sha256_32bit_entry,_sha256_32bit_entry+8,this->sha256_32bit_entry);
}

Sha2::~Sha2()
{
    delete[] this->msg_block.block;
}

auto Sha256::operator==(const Sha256 hashedMessage)
{
    for(int i=0;i<8;i++)
    {
        if(this->sha256_32bit_entry[i] != hashedMessage.sha256_32bit_entry[i])
        {
            return false;
        }
    }
    return true;
}

void Sha256::hash_sha256(const uint32_t* input, uint32_t sha256_32bit_entry[8])
{
    uint32_t la = sha256_32bit_entry[0];
    uint32_t lb = sha256_32bit_entry[1];
    uint32_t lc = sha256_32bit_entry[2];
    uint32_t ld = sha256_32bit_entry[3];
    uint32_t le = sha256_32bit_entry[4];
    uint32_t lf = sha256_32bit_entry[5];
    uint32_t lg = sha256_32bit_entry[6];
    uint32_t lh = sha256_32bit_entry[7];

    for(int i=0;i<64;i++)
    {
        uint32_t S1 = (ROTATE(le, 6) ^ ROTATE(le, 11) ^ ROTATE(le, 25));
        uint32_t ch = (le & lf) ^ ((~le) & lg);
        uint32_t temp1 = lh + S1 + ch + k[i] + input[i];
        uint32_t S0 = (ROTATE(la, 2) ^ ROTATE(la, 13) ^ ROTATE(la, 22));
        uint32_t maj = (la & lb) ^ (la & lc) ^ (lb & lc);
        uint32_t temp2 = S0 + maj;

        lh = lg;
        lg = lf;
        lf = le;
        le = ld + temp1;
        ld = lc;
        lc = lb;
        lb = la;
        la = temp1 + temp2;
    }

    sha256_32bit_entry[0] += la;
    sha256_32bit_entry[1] += lb;
    sha256_32bit_entry[2] += lc;
    sha256_32bit_entry[3] += ld;
    sha256_32bit_entry[4] += le;
    sha256_32bit_entry[5] += lf;
    sha256_32bit_entry[6] += lg;
    sha256_32bit_entry[7] += lh;
}

void Sha256::pre_process_step(const uint8_t* chunk, uint32_t chunk_32bit_entry[64])
{
    for(int i=0;i<64;i++)
    {
        // Yeah I know it's ugly, but if you know bitwise operations, it makes sense...
        chunk_32bit_entry[i/4] = (chunk[i] << (24 - ((i%4) * 8))) | chunk_32bit_entry[i/4];
    }

    for(int i=16;i<64;i++)
    {
        uint32_t s0 = (ROTATE(chunk_32bit_entry[i-15], 7) ^ ROTATE(chunk_32bit_entry[i-15], 18) ^ (chunk_32bit_entry[i-15] >> 3));
        uint32_t s1 = (ROTATE(chunk_32bit_entry[i-2], 17) ^ ROTATE(chunk_32bit_entry[i-2], 19) ^ (chunk_32bit_entry[i-2] >> 10));
        chunk_32bit_entry[i] = chunk_32bit_entry[i-16] + s0 + chunk_32bit_entry[i-7] + s1;
    }
}

void Sha256::build_msg_block(const string input, message_block* msg)
{
    const uint remaining_bits=64-((input.length()+1+8)%64);
    msg->length = (input.length()+1+8)+remaining_bits;;
    msg->block = new uint8_t[msg->length];
    memset(msg->block, 0, msg->length * sizeof(uint8_t));

    memcpy(msg->block,input.data(),input.length() * sizeof(uint8_t));
    msg->block[input.length()] = 0b10000000;

    uint64_t stringlengthInBit =input.length() * 8;
    for(size_t i=0;i<8;i++)
    {
        msg->block[(msg->length-8)+i] = stringlengthInBit >> (56 - 8 * i) & 0xFF;
    }
}

void printSha256(const uint32_t* sha256Hash)
{
    for(int i=0;i<8;i++)
    {
        cout << std::hex << static_cast<uint>(sha256Hash[i]) << ' ';
    }
    cout << std::dec << endl;
}

// Temporary function, since operator== is not working with base class
bool tempSha256Check(uint32_t a[8], uint32_t b[8])
{
    for(int i=0;i<8;i++)
    {
        if(a[i] != b[i])
        {
            return false;
        }
    }
    return true;
}

void testSha256Hash(const string inputString, const uint32_t* expectedSha2Hash)
{
    Sha2* hashedString = new Sha256(inputString);
    Sha2* expectedSha256 = new Sha256(expectedSha2Hash);

    string testResult;
    if(tempSha256Check(hashedString->sha256_32bit_entry, expectedSha256->sha256_32bit_entry))
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
    printSha256(expectedSha2Hash);
    cout << "Actual hash =>\n";
    printSha256(hashedString->sha256_32bit_entry);
    cout << "================================================================================================\n\n";
    delete hashedString;
    delete expectedSha256;
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
