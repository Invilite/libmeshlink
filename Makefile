# sudo apt install libgtest-dev

CXX = g++
MAKEFLAGS += -j$(nproc)
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic -fPIC -fstack-protector-all
DEPFLAGS = -MMD -MP                                         # emit .d files so header edits rebuild every dependent object
LDFLAGS = ../botan/libbotan-3.a

STATIC_LIB = libmeshlink.a
SHARED_LIB = libmeshlink.so
INCLUDE = -I./include -I../botan/build/include/public
SOURCES = $(wildcard src/*.cpp) $(wildcard libs/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)
TEST_SOURCES = $(wildcard tests/*.cpp)
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)
TEST_BINARY = run_test

all: CXXFLAGS += -O2 -flto
all: LDFLAGS += -flto
all: $(STATIC_LIB) $(SHARED_LIB)

dev: CXXFLAGS += -g -fsanitize=thread -fsanitize=undefined
dev: LDFLAGS += -fsanitize=thread -fsanitize=undefined
dev: $(STATIC_LIB) $(SHARED_LIB)

$(STATIC_LIB): $(OBJECTS)
	ar rcs $@ $^

$(SHARED_LIB): $(OBJECTS)
	$(CXX) -shared -o $@ $^ $(LDFLAGS)

tests: $(TEST_OBJECTS) $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) -o $(TEST_BINARY) $(TEST_OBJECTS) $(STATIC_LIB) $(LDFLAGS) -lgtest_main -lgtest -lpthread

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) $(INCLUDE) -c $< -o $@

tests/%.o: tests/%.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) $(INCLUDE) -c $< -o $@

.PHONY: clean

clean:
	rm -f $(OBJECTS) $(STATIC_LIB) $(SHARED_LIB) $(TEST_OBJECTS) $(TEST_BINARY) $(OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)

-include $(OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
