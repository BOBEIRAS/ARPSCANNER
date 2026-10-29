CC      = gcc
CFLAGS  = -Wall -Wextra -O2
CPPFLAGS = -Iinclude
BIN     = netmap
SRC     = $(wildcard src/*.c)
OBJ     = $(patsubst src/%.c,build/%.o,$(SRC))

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ)

build/%.o: src/%.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build:
	mkdir -p $@

install: $(BIN)
	sudo install -m 755 $(BIN) /usr/local/bin/$(BIN)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(BIN)

install-agent: $(BIN)
	sudo install -m 755 $(BIN) /usr/local/bin/$(BIN)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(BIN)
	sudo install -d -m 755 /usr/local/lib/netmap
	sudo install -m 755 tools/alert_agent.py /usr/local/lib/netmap/alert_agent.py
	sudo install -m 644 netmap-alert-agent.service /etc/systemd/system/netmap-alert-agent.service
	sudo systemctl daemon-reload

install-dashboard:
	sudo install -d -m 755 /usr/local/lib/netmap/dashboard/templates
	sudo install -m 755 dashboard/app.py /usr/local/lib/netmap/dashboard/app.py
	sudo install -m 644 dashboard/requirements.txt /usr/local/lib/netmap/dashboard/requirements.txt
	sudo install -m 644 dashboard/templates/dashboard.html /usr/local/lib/netmap/dashboard/templates/dashboard.html
	sudo python3 -m venv /usr/local/lib/netmap/venv
	sudo /usr/local/lib/netmap/venv/bin/pip install --disable-pip-version-check -r /usr/local/lib/netmap/dashboard/requirements.txt
	sudo install -m 644 netmap-dashboard.service /etc/systemd/system/netmap-dashboard.service
	sudo systemctl daemon-reload

clean:
	rm -f $(BIN) $(OBJ)
	rmdir build 2>/dev/null || true

.PHONY: all install clean