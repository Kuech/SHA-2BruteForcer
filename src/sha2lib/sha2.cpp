#include "sha2.h"
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>

// Check out https://sha256algorithm.com/
using namespace std;

uint32_t h[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

uint32_t k[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 
};

uint8_t* hash_sha256(uint32_t* input)
{
    uint32_t la = h[0];
    uint32_t lb = h[1];
    uint32_t lc = h[2];
    uint32_t ld = h[3];
    uint32_t le = h[4];
    uint32_t lf = h[5];
    uint32_t lg = h[6];
    uint32_t lh = h[7];

    for(int i=0;i<64;i++)
    {
        uint32_t S1 = (ROTATE(le, 6) ^ ROTATE(le, 11) ^ ROTATE(le, 25));
        uint32_t ch = (le & lf) ^ ((~le) & lg);
        uint32_t temp1 = lh + S1 + ch + k[i] + input[i];
        uint32_t S0 (ROTATE(la, 2) ^ ROTATE(la, 13) ^ ROTATE(la, 22));
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

    h[0] += la;
    h[1] += lb;
    h[2] += lc;
    h[3] += ld;
    h[4] += le;
    h[5] += lf;
    h[6] += lg;
    h[7] += lh;

    uint8_t* sha256 = new uint8_t[32];

    for(int i=0;i<32;i++)
    {
        sha256[i] = h[i/4] >> (24 - ((i%4)*8));
    }

    return sha256;
}

uint32_t* pre_process_step(uint8_t* input)
{
    uint32_t* word = new uint32_t[64];

    for(int i=0;i<64;i++)
    {
        // Yeah I know it's ugly, but if you know bitwise operations, it makes sense...
        word[i/4] = (input[i] << (24 - ((i%4) * 8))) | word[i/4];
    }

    for(int i=16;i<64;i++)
    {
        uint32_t s0 = (ROTATE(word[i-15], 7) ^ ROTATE(word[i-15], 18) ^ (word[i-15] >> 3));
        uint32_t s1 = (ROTATE(word[i-2], 17) ^ ROTATE(word[i-2], 19) ^ (word[i-2] >> 10));
        word[i] = word[i-16] + s0 + word[i-7] + s1;
    }
    return word;
}

uint8_t* build_msg_block(const char* input)
{
    uint length = strlen(input);
    /*
    if(strlen(input) > 56)
    {
        cout << "Message too long" << '\n';
        return nullptr_t();
    }
    */

    uint8_t* msg_block = new uint8_t[64];
    const char* end = &input[length];
    uint count = 0;
    while(input<end)
    {
        msg_block[count] = *input;
        count++;
        input++;
    }

    msg_block[count] = 0b10000000;
    count++;

    for(uint i=count;i<56;i++)
    {
        msg_block[i] = 0;
    }

    uint64_t lenghInBit =length * 8;
    for(size_t i=0;i<8;i++)
    {
        msg_block[56+i] = lenghInBit >> (56 - 8 * i) & 0xFF;
    }

    return msg_block; // message length
}

void printSha256(const uint8_t* sha256Hash)
{
    for(int i=0;i<32;i++)
    {
        cout << std::hex << static_cast<uint>(sha256Hash[i]) << ' ';
    }
    cout << '\n';
}

void testSha256Hash(const char* inputString, const uint8_t* expectedSha2Hash)
{
    uint8_t* msg_block = build_msg_block(inputString);
    uint32_t* pre_proc_msg = pre_process_step(msg_block);
    uint8_t* sha256Hash = hash_sha256(pre_proc_msg);
    bool isTestSuccess = true;

    // SHA-256
    for(int i=0;i<32;i++)
    {
        if(sha256Hash[i] != expectedSha2Hash[i])
        {
            isTestSuccess = false;
        }
    }

    string testResult;
    if(isTestSuccess)
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
    printSha256(sha256Hash);
    cout << "================================================================================================\n\n";

    destroy(msg_block, msg_block+64);
    destroy(pre_proc_msg, pre_proc_msg+64);
    destroy(sha256Hash, sha256Hash+32);
}

int main() {
    static const string testString = "aaa";
    // 64‑hex‑digit literal → 32 bytes
    static const uint8_t data[32] = {
        0x98, 0x34, 0x87, 0x6d, 0xcf, 0xb0, 0x5c, 0xb1,
        0x67, 0xa5, 0xc2, 0x49, 0x53, 0xeb, 0xa5, 0x8c,
        0x4a, 0xc8, 0x9b, 0x1a, 0xdf, 0x57, 0xf2, 0x8f,
        0x2f, 0x9d, 0x09, 0xaf, 0x10, 0x7e, 0xe8, 0xf0
    };

    const string testString2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const uint8_t data2[32] = {
        0x31, 0xeb, 0xa5, 0x1c, 0x31, 0x3a, 0x5c, 0x08,
        0x22, 0x6a, 0xdf, 0x18, 0xd4, 0xa3, 0x59, 0xcf,
        0xdf, 0xd8, 0xd2, 0xe8, 0x16, 0xb1, 0x3f, 0x4a,
        0xf9, 0x52, 0xf7, 0xea, 0x65, 0x84, 0xdc, 0xfb
    };

    testSha256Hash(testString.data(), data);
    //testSha256Hash(testString2.data(), data2);
}
