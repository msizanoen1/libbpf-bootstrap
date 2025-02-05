PREFIX ?= /usr/local

LIBDECOR_LSM = ../examples/c/libdecor_lsm

all: $(LIBDECOR_LSM)

clean:
	$(MAKE) -C ../examples/c clean

install: all
	install -v -m 0700 -Dt $(PREFIX)/libexec $(LIBDECOR_LSM)
	install -v -m 0644 -Dt $(PREFIX)/lib/systemd/system libdecor_lsm.service

uninstall:
	rm -vf $(PREFIX)/libexec/libdecor_lsm $(PREFIX)/lib/systemd/system/libdecor_lsm.service

$(LIBDECOR_LSM):
	$(MAKE) -C ../examples/c libdecor_lsm

.PHONY: all clean install uninstall $(LIBDECOR_LSM)
