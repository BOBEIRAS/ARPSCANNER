CC      = gcc
CFLAGS  = -Wall -Wextra -O2
BIN     = netmap
SRC     = $(wildcard *.c)
OBJ     = $(SRC:.c=.o)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(BIN)
	sudo install -m 755 $(BIN) /usr/local/bin/$(BIN)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(BIN)

clean:
	rm -f $(BIN) *.o