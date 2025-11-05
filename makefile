COMPILER=g++

brute: src/brute.o src/sha2/sha2.o
	$(COMPILER) $^ -o $@

src/brute.o: src/brute.cpp
	$(COMPILER) -std=c++17 -Wall -Wextra -c $^ -o $@

src/sha2/sha2.o:
	cd src/sha2 && make

sha2libTest: src/sha2lib/sha2.cpp
	$(COMPILER) -std=c++17 -Wall -Wextra $^ -o $@

clean:
	rm -f brute src/brute.o src/sha2/sha2.o
