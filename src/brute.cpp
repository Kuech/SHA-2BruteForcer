#include <iostream>
#include <fstream>
#include <sys/types.h>
#include "sha2/sha2.h"

#define MSG_USAGE "usage : brute <SHA-2-HashFunction> <SHA-2-HashValue> example_dict.txt"
#define MSG_FOUND "Match found! : "
#define EXC_NOFILE 42
#define EXC_INVALIDHASH 1
#define MAX_WORDS 65536

using namespace std;

enum HashType
{
    SHA224,
    SHA256,
    SHA384,
    SHA512
};

struct WordList
{
    string *words;
    uint count;
};

struct HashProperties
{
    HashType hash_type;
    uint digest_size;
    uint string_hash_length;
};

class Hash
{
private:
    void HashWord(string word)
    {
        switch(_hash_properties.hash_type)
        {
            case SHA224:
                sha224((const uint8 *)word.data(), word.length(),_digest);
            break;
            case SHA256:
                sha256((const uint8 *)word.data(), word.length(),_digest);
            break;
            case SHA384:
                sha384((const uint8 *)word.data(), word.length(),_digest);
            break;
            case SHA512:
                sha512((const uint8 *)word.data(), word.length(),_digest);
            break;
        }
    }

    void SetHashProperties(HashType hash_type)
    {
        switch(hash_type) {
            case SHA224:
                _hash_properties.digest_size = SHA224_DIGEST_SIZE;
                _hash_properties.string_hash_length = SHA224_DIGEST_SIZE*2;
            break;
            case SHA256:
                _hash_properties.digest_size = SHA256_DIGEST_SIZE;
                _hash_properties.string_hash_length = SHA256_DIGEST_SIZE*2;
            break;
            case SHA384:
                _hash_properties.digest_size = SHA384_DIGEST_SIZE;
                _hash_properties.string_hash_length = SHA384_DIGEST_SIZE*2;
            break;
            case SHA512:
                _hash_properties.digest_size = SHA512_DIGEST_SIZE;
                _hash_properties.string_hash_length = SHA512_DIGEST_SIZE*2;
            break;
        }
        _hash_properties.hash_type = hash_type;
    }

    HashType GetHashTypeFromString(string hash_type_string)
    {
        if(hash_type_string == "sha224")
        {
            return SHA224;
        }
        if(hash_type_string == "sha256")
        {
            return SHA256;
        }
        if(hash_type_string == "sha384")
        {
            return SHA384;
        }
        if(hash_type_string == "sha512")
        {
            return SHA512;
        }
        throw 2;
    }

public:
    uint8* _digest;
    HashProperties _hash_properties;

    Hash(HashType hash_type, string SHA2HashedString)
    {
        SetHashProperties(hash_type);
        if(SHA2HashedString.length() != _hash_properties.string_hash_length)
        {
            throw 1;
        }
        _digest = new uint8[_hash_properties.digest_size];

        char* hashed_string = &SHA2HashedString.data()[0];
        for(int i=0;i<_hash_properties.digest_size;i++)
        {
            char hex_string[] = { hashed_string[0], hashed_string[1] };
            _digest[i] = stoi(hex_string,0,16);
            hashed_string = hashed_string + 2;
        }
    }

    Hash(string hash_type_string, string SHA2HashedString) : Hash(GetHashTypeFromString(hash_type_string), SHA2HashedString)
    {}

    string HashInStringHex()
    {
        char hashOutput[2 * SHA512_DIGEST_SIZE + 1];
        hashOutput[2 * _hash_properties.digest_size] = '\0';
        for(int i=0;i<(int) _hash_properties.digest_size; i++)
        {
            sprintf(hashOutput + 2 * i, "%02x", _digest[i]);
        }

        return string(hashOutput);
    }
};

WordList ReadWordListFile(string filename);
// To be removed when implementation is done
string HashWord(string word);

int main(int argc, char** argv)
{
    if (argc <= 3)
    {
        cout << MSG_USAGE << endl;
        return 1;
    }
    string sha2_mode = argv[1];
    string sha2_input = argv[2];
    string dictionary_file = argv[3];
    Hash inputHash = Hash(sha2_mode,sha2_input);
    WordList wordList;
    try
    {
        wordList = ReadWordListFile(dictionary_file);
    }
    catch(int code)
    {
        cout << "Code " << code << "\n" << "No file for " << dictionary_file << endl;
        return -1;
    }

    for(uint i=0;i<wordList.count;i++)
    {
        string output = HashWord(wordList.words[i]);
        if (sha2_input.compare(output) == 0)
        {
            cout << MSG_FOUND << output << " | " << wordList.words[i] << endl;
        }
    }

    cout << "finished..." << '\n';
    return 0;
}

WordList ReadWordListFile(string filename)
{
    ifstream inputFile;
    string wordList[MAX_WORDS];

    // open dictionary filename
    inputFile.open(filename);
    uint wordCount=0;
    if(inputFile.is_open())
    {
        while ( getline(inputFile,wordList[wordCount]))
        {
            wordCount++;
        }
        inputFile.close();
    }
    else{
        throw EXC_NOFILE;
    }

    return WordList{wordList, wordCount};
}

// To be removed when implementation is done
string HashWord(string word)
{
    // Code is taken from the test in sha-2
    uint8 digest[SHA224_DIGEST_SIZE];
    sha224((const uint8 *)word.data(), word.length(),digest);

    char hashOutput[2 * SHA512_DIGEST_SIZE + 1];
    hashOutput[2 * SHA224_DIGEST_SIZE] = '\0';
    for(int i=0;i<(int) SHA224_DIGEST_SIZE; i++)
    {
        sprintf(hashOutput + 2 * i, "%02x", digest[i]);
    }

    return string(hashOutput);
}
