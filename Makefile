C = gcc
CFLAGS = -Wall -g -O2
LDFLAGS = 
SOURCES = based_data.c myserver.c database.c
OBJECTS = $(SOURCES:.c=.o)
	EXECUTABLE = based

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
		$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		rm -f $(OBJECTS) $(EXECUTABLE)

.PHONY: all clean
