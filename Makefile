# sudo apt install libcrypto++8

CXX = g++
MAKEFLAGS += -j$(nproc)
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -fstack-protector-all
LDFLAGS = -pthread -lcryptopp -lrt -static-libstdc++ -static-libgcc
#LDFLAGS = -pthread -lsfml-graphics -lsfml-window -lsfml-system

TARGET = meshlinkd
INCLUDE = -I./include
SOURCES = $(wildcard src/*.cpp) $(wildcard libs/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

all: CXXFLAGS += -O2 -flto
all: LDFLAGS += -flto -static
all: $(TARGET)

dev: CXXFLAGS += -g -fsanitize=thread -fsanitize=undefined
dev: LDFLAGS += -fsanitize=thread -fsanitize=undefined
dev: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

.PHONY: clean

clean:
	rm -f $(OBJECTS) $(TARGET)