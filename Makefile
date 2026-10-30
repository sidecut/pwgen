PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

.PHONY: all test install clean

all: pwgen

pwgen: main.go go.mod
	go build -o $@ .

test:
	go test ./...

install: pwgen
	install -D -m 755 pwgen $(DESTDIR)$(BINDIR)/pwgen
	install -D -m 644 pwgen.1 $(DESTDIR)$(MANDIR)/man1/pwgen.1

clean:
	rm -f pwgen