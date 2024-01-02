# sudo apt install libcrypto++8

CXX = g++
MAKEFLAGS += -j$(nproc)
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS = -pthread -lcryptopp -static -static-libstdc++ -static-libgcc
#LDFLAGS = -pthread -lsfml-graphics -lsfml-window -lsfml-system

TARGET = meshlinkd
INCLUDE = -I./include
SOURCES = $(wildcard src/*.cpp) $(wildcard libs/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

.PHONY: clean

clean:
	rm -f $(OBJECTS) $(TARGET)