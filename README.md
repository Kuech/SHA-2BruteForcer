# Brute

A program that bruteforce SHA-2 hashed password from a word list file.

## Usage

`brute 0808f64e60d58979fcb676c96ec938270dea42445aeefcd3a4e6f8db example_words.txt`

Where `0808f64e60d58979fcb676c96ec938270dea42445aeefcd3a4e6f8db` is a sha-2 hash (more precisely sha-224) of the word 'foo'.
`example_words.txt` is the word list file. In this file you place all possible words that can potentially match with the sha-2 hash when hashed.

If `example_words.txt` contain the word 'foo', then we will have this output :

```bash
./brute 0808f64e60d58979fcb676c96ec938270dea42445aeefcd3a4e6f8db example_words.txt
Match found! : 0808f64e60d58979fcb676c96ec938270dea42445aeefcd3a4e6f8db | foo
finished...
```

If not then nothing will be displayed.

### Build

* CLI : `make brute`

## SHA-2 implementation

The sha-2 header is from another [git repo](https://github.com/ogay/sha2).
This implementation is written in C. I just simply took this and adapt to my C++ code.

## Milestone

* [x] First working version.
    * [x] sha-224
    * [ ] sha-256
    * [ ] sha-384
    * [ ] sha-512
* [] benchmark performance
* [] implement multithreading
* [] implement parallel calculations
