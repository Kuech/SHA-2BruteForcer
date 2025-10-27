sha2Folder = sha2

brute: brute.o sha2/sha2.o
	g++ $^ -o $@

brute.o: brute.cpp
	g++ -std=c++17 -Wall -Wextra -c $^ -o $@

sha2/sha2.o:
	cd sha2 && make
clean:
	rm -f brute brute.o sha2/sha2.o
