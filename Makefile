Target = name
CC=g++
SOURCES=$(wildcard *.cpp)
OBJECTS=$(SOURCES:.cpp=.o)
all: $(SOURCES) $(Target)
$(Target): $(OBJ)
	$(CC) $(OBJ) -o $@
.cpp.o:
	$(CC) $< -o $@