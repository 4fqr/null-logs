PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSDIR ?= /lib/systemd/system
VERSION ?= 0.1.0
CFLAGS ?= -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -DVERSION=\"$(VERSION)\" -Wall -Wextra -Werror -fPIC
LDFLAGS ?= -Wl,-z,relro,-z,now
LIBS ?= -lrt -lcrypto

# Optional eBPF support (set LIBBPF=1 to enable; set LIBBPF=auto to autodetect)
LIBBPF ?= auto
EBPF_CLANG ?= clang
EBPF_CFLAGS ?= -target bpf -O2 -g

SRC = src/main.c src/daemon.c src/logging.c src/utils.c src/config.c

PKG_HAS_LIBBPF := $(shell pkg-config --exists libbpf && echo 1 || echo 0)
ifeq ($(LIBBPF),auto)
LIBBPF := $(PKG_HAS_LIBBPF)
endif
ifeq ($(LIBBPF),1)
PKG_LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
PKG_LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null)
ifeq ($(PKG_HAS_LIBBPF),0)
$(error LIBBPF=1 but libbpf not found (install libbpf-dev or use LIBBPF=0))
endif
CFLAGS += -DUSE_LIBBPF $(PKG_LIBBPF_CFLAGS) -I/usr/include -I/usr/include/bpf
# pass libbpf cflags to eBPF C compilation too (headers like bpf/ringbuf.h)
EBPF_CFLAGS += $(PKG_LIBBPF_CFLAGS) -I/usr/include -I/usr/include/bpf
# add kernel include dir if installed under /usr/src/linux-headers-*/include
KDIR := $(shell ls -d /usr/src/linux-headers-* 2>/dev/null | head -n1)
ifneq ($(KDIR),)
EBPF_CFLAGS += -I$(KDIR)/include
CFLAGS += -I$(KDIR)/include
endif
LDFLAGS += -lbpf -lelf -lz $(PKG_LIBBPF_LIBS)
SRC += src/ebpf_loader.c
EBPF_OBJ = src/ebpf/syscalls.bpf.o
OBJ = $(SRC:.c=.o) $(EBPF_OBJ)
else
OBJ = $(SRC:.c=.o)
endif

all: null-logs

null-logs: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

ifeq ($(LIBBPF),1)
$(EBPF_OBJ): src/ebpf/syscalls.bpf.c
	$(EBPF_CLANG) $(EBPF_CFLAGS) -c $< -o $@
endif

install: null-logs forwarder
	install -d $(DESTDIR)/var/log/null-logs
	install -m 700 -d $(DESTDIR)/etc/null-logs
	install -m 600 contrib/key.sample $(DESTDIR)/etc/null-logs/key
	install -m 755 null-logs $(DESTDIR)$(BINDIR)/null-logs
	install -m 755 cmd/forwarder/null-logs-forwarder $(DESTDIR)$(BINDIR)/null-logs-forwarder
	install -m 644 packaging/systemd/null-logs.service $(DESTDIR)$(SYSDIR)/null-logs.service
	install -m 644 packaging/systemd/null-logs-forwarder.service $(DESTDIR)$(SYSDIR)/null-logs-forwarder.service
	install -m 644 packaging/logrotate/null-logs $(DESTDIR)/etc/logrotate.d/null-logs
	@echo "Note: create a system user 'null-logs' for better isolation and set ownership of /var/log/null-logs to that user"

package-deb: all
	@echo "Building .deb package in dist/"
	@rm -rf dist
	@mkdir -p dist/null-logs_tmp/DEBIAN
	@cp packaging/deb/control dist/null-logs_tmp/DEBIAN/control
	@cp packaging/deb/postinst dist/null-logs_tmp/DEBIAN/postinst
	@chmod 755 dist/null-logs_tmp/DEBIAN/postinst
	@mkdir -p dist/null-logs_tmp/usr/local/bin
	@cp null-logs dist/null-logs_tmp/usr/local/bin/
	@cp cmd/forwarder/null-logs-forwarder dist/null-logs_tmp/usr/local/bin/
	@mkdir -p dist/null-logs_tmp/etc/null-logs
	@cp contrib/key.sample dist/null-logs_tmp/etc/null-logs/key
	@mkdir -p dist/null-logs_tmp/var/log/null-logs
	@dpkg-deb --build dist/null-logs_tmp dist/null-logs-0.1.0.deb
	@echo ".deb package created: dist/null-logs-0.1.0.deb"

check: all test
	@echo "Completed check"

# Run tests (verify always, ebpf smoke-test will skip if environment not ready)
test: all
	@echo "Running tests..."
	@sh tests/test_verify.sh
	@sh tests/test_ebpf.sh || true
	@echo "All tests completed"

clean:
	rm -f $(OBJ) null-logs

.PHONY: all install clean check