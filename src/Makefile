CC = gcc
CFLAGS = -Wall -g -O2
LDFLAGS = -lz -lcrypto -pthread
SOURCES = cli.c database.c myserver.c base64.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = cli

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
		$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		rm -f $(OBJECTS) $(EXECUTABLE)

.PHONY: all clean
