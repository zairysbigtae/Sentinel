BIN_PATH = target/release/sentinel_src
PREFIX = /usr/local/

all: $(BIN_PATH)

build:
	cargo build --release

install:
	cp $(BIN_PATH) $(PREFIX)/bin

enable-daemon:
	set -e
	install -m 644 sentinel.service /etc/systemd/system/ 
	systemctl daemon-reload
	
	echo "Installed Sentinel's daemon"
