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

enum localVarName { la=0, lb=1, lc=2, ld=3, le=4, lf=5, lg=6, lh=7};

uint8_t* build_msg_block(char* input);
uint32_t* pre_process_step(uint8_t* input);

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



uint8_t* build_msg_block(char* input)
{
    uint length = strlen(input);
    if(strlen(input) > 56)
    {
        cout << "Message too long" << '\n';
        return nullptr_t();
    }

    uint8_t* msg = new uint8_t[64]; // 512 bit
    char* end = &input[length];
    uint count = 0;
    while(input<end)
    {
        msg[count] = *input;
        count++;
        input++;
    }

    msg[count] = 0b10000000;
    count++;

    for(uint i=count;i<56;i++)
    {
        msg[i] = 0;
    }

    uint64_t lenghInBit =length * 8;
    for(size_t i=0;i<8;i++)
    {
        msg[56+i] = lenghInBit >> (56 - 8 * i) & 0xFF;
    }

    return msg;
}

int main(int argc, char **argv) {

    uint8_t* msg = build_msg_block(argv[1]);
    uint32_t* pre_proc_msg = pre_process_step(msg);
    uint8_t* sha256Hash = hash_sha256(pre_proc_msg);

    /*
    // message block init
    for(int i=0;i<16;i++)
    {
        for(int j=0;j<4;j++)
        {
            cout << bitset<8>(msg[(i*4)+j]) << ' ';
        }
        cout << '\n';
    }
    */
    
    /*
    // pre process step
    for(int i=0;i<64;i++)
    {
        cout << bitset<32>(pre_proc_msg[i]) << '\n';
    }
    */

    uint32_t test = 0xa0b0c0d0;
    uint8_t test1 = test;
    cout << "test : " << bitset<8>(test1) << '\n';

    // SHA-256
    for(int i=0;i<8;i++)
    {
        for(int j=0;j<4;j++)
        {
            cout << std::hex << (uint)sha256Hash[(i*4)+j] << ' ';
        }
        cout << '\n';
    }

    destroy(msg, msg+64);
    destroy(pre_proc_msg, pre_proc_msg+64);
    destroy(sha256Hash, sha256Hash+32);
}
