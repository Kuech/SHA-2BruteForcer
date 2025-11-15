COMPILER=g++
CPP_VERSION=-std=c++17
BUILD=$(COMPILER) $(CPP_VERSION) -Wall -Wextra -O2 -fsanitize=address,undefined

BUILD_FOLDER=bin

$(BUILD_FOLDER)/brute: src/brute.o src/sha2/sha2.o $(BUILD_FOLDER)
	$(COMPILER) $^ -o $@

src/brute.o: src/brute.cpp
	$(BUILD) -c $^ -o $@

src/sha2/sha2.o:
	cd src/sha2 && make

$(BUILD_FOLDER)/sha2libTest: src/sha2lib/sha2.cpp src/sha2lib/sha2.h
	mkdir -p $(BUILD_FOLDER)
	$(BUILD) $^ -o $@

clean:
	rm -rf bin

.PHONY: clean $(BUILD_FOLDER)
