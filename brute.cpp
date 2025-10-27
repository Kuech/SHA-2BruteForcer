/*
 *
 * Bruteforce
 *
*/

#include <iostream>
#include <fstream>
#include <sys/types.h>
#include "sha2/sha2.h"

using namespace std;

uint ReadDictionnaryFile(char* filename, string* wordList);

int main(int argc, char** argv) {

    if ( argc <= 2)
    {
        cout << "usage : brute foo dict.txt" << endl;
        return 1;
    }

    string sha2Input = string(argv[1]);
    char* dictionaryFilename = argv[2];
    string* wordlist = new string[2056];

    uint lines = ReadDictionnaryFile(dictionaryFilename, wordlist);
    for(uint i=0;i<lines;i++)
    {
        uint8 digest[SHA224_DIGEST_SIZE];
        sha224((const uint8 *)wordlist[i].data(), wordlist[i].length(),digest);
        
        char output[2 * SHA512_DIGEST_SIZE + 1];
        int j;
        output[2 * SHA224_DIGEST_SIZE] = '\0';
        for(j=0;j<(int) SHA224_DIGEST_SIZE; j++){
            sprintf(output + 2 * j, "%02x", digest[j]);
        }

        if (sha2Input.compare(output) == 0)
        {
            cout << "Match found! : " << output << " | " << wordlist[i] << endl;
        }
    }

    cout << "finished..." << endl;
    return 0;
}

uint ReadDictionnaryFile(char* filename, string* wordList)
{
    ifstream inputFile;
    string line;

    // open dictionary filename
    inputFile.open(filename);
    uint i=0;
    if(inputFile.is_open())
    {
        while ( getline(inputFile,wordList[i]))
        {
            i++;
        }
    }
    inputFile.close();
    return i;
}
