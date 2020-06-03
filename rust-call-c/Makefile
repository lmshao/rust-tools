CC = gcc
LD = gcc

SRC = $(wildcard *.c)
OBJ = $(patsubst %c, %o, $(SRC))

CPPFLAGS =
LDFLAGS = -L./ -lcapitalize

TARGET = HelloWorld

.PHONY: all clean lib
all: $(TARGET)

$(TARGET) : $(OBJ) lib
	$(LD) -g -o $@ $< $(LDFLAGS)

%.o:%.c
	$(CC) $(CPPFLAGS) -g -c $^

lib: capitalize.rs
	rustc --crate-type=staticlib capitalize.rs

clean:
	rm -f $(OBJ) $(TARGET) libcapitalize.*
