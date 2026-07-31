CXX      := g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2
LDLIBS   := -lpcap
TARGET   := packet_analyzer
SRC      := src/main.cpp

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
