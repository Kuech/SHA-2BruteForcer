COMPILER=g++

brute: src/brute.o src/sha2/sha2.o
	$(COMPILER) $^ -o $@

src/brute.o: src/brute.cpp
	$(COMPILER) -std=c++17 -Wall -Wextra -c $^ -o $@

src/sha2/sha2.o:
	cd src/sha2 && make
clean:
	rm -f brute src/brute.o src/sha2/sha2.o
