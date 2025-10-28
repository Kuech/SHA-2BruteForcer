#include <iostream>
#include <fstream>
#include <sys/types.h>
#include "sha2/sha2.h"

using namespace std;

#define MSG_USAGE "usage : brute <SHA-224> example_dict.txt"
#define MSG_FOUND "Match found! : "
#define EXC_NOFILE 42
#define MAX_WORDS 2056

struct WordList
{
    string *words;
    uint count;
};


WordList ReadWordListFile(string filename);
string HashWord(string word);

int main(int argc, char** argv)
{
    if (argc <= 2)
    {
        cout << MSG_USAGE << endl;
        return 1;
    }

    string sha2_input = argv[1];
    string dictionary_file = argv[2];
    WordList wordList;
    try
    {
        wordList = ReadWordListFile(dictionary_file);
    }
    catch(int code)
    {
        cout << "Code " << code << "\n" << "No file for " << dictionary_file << "\n";
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

    cout << "finished..." << endl;
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
