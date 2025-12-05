BIN_PATH = target/release/sentinel
PREFIX = /usr/local

all: $(BIN_PATH)

build:
	@echo "OUT_DIR: $(shell cargo metadata --format-version 1 | jq -r '.target_directory')/release/build/sentinel-*/out/"
	@ls -l target/release/build/sentinel-*/out/
	LIEF_WRAPPER_PATH=/usr/local/lib/ \
	RUSTFLAGS=-Awarnings cargo build --release

install:
	rm -rf $(PREFIX)/bin/sentinel
	cp $(BIN_PATH) $(PREFIX)/bin
	cp c_code/exe/liblief_wrapper.so $(PREFIX)/lib
	mkdir -p $(PREFIX)/share/sentinel
	test -f $(PREFIX)/share/sentinel/passwd.db || touch $(PREFIX)/share/sentinel/passwd.db
	sudo chown $(USER) $(PREFIX)/share/sentinel/passwd.db
	sudo chmod 666 $(PREFIX)/share/sentinel/passwd.db
	sudo chmod 777 $(PREFIX)/share/sentinel/

enable-daemon:
	set -e
	install -m 644 sentinel.service /etc/systemd/system/
	systemctl daemon-reload
	
	sudo systemctl stop sentinel
	sudo systemctl disable sentinel
	sudo systemctl start sentinel
	sudo systemctl enable sentinel
