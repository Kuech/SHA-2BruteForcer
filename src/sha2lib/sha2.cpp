#include "sha2.h"
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>

// Check out https://sha256algorithm.com/
using namespace std;

uint8_t* build_msg_block(char* input);

uint8_t* hash_sha256(uint8_t* input)
{
    return nullptr_t();
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

    for(int i=0;i<16;i++)
    {
        for(int j=0;j<4;j++)
        {
            cout << bitset<8>(msg[(i*4)+j]) << ' ';
        }
        cout << '\n';
    }
    destroy(msg, msg+64);
}
