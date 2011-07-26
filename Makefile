CFLAGS=-DDESTDIR=$(DESTDIR) -DHELPER_NAME=\"$(DESTDIR)/bin/tor-arm-replace-torrc.py\"

# We must have these to actually function
USER="tor-arm"
GROUP="tor-arm"

all: tor-arm-replace-torrc
clean:
	rm tor-arm-replace-torrc

install: all
	[ -d $(DESTDIR)/bin/ ] || mkdir -p $(DESTDIR)/bin/
	[ -d $(DESTDIR)/var/lib/tor-arm/ ] || mkdir -p $(DESTDIR)/var/lib/tor-arm/
	addgroup --system $(GROUP)
	adduser --ingroup $(GROUP) --no-create-home --home $(DESTDIR)/var/lib/tor-arm/ --shell /bin/sh --system $(USER)
	chown root:root $(DESTDIR)/bin/
	chown root:$(GROUP) $(DESTDIR)/var/lib/tor-arm/
	chmod 750 $(DESTDIR)/var/lib/tor-arm/
	install -o root -g $(GROUP) -m 04750 -s tor-arm-replace-torrc $(DESTDIR)/bin/tor-arm-replace-torrc 
	install -o root -g root -m 0755 tor-arm-replace-torrc.py $(DESTDIR)/bin/tor-arm-replace-torrc.py 
	install -o root -g $(GROUP) torrc $(DESTDIR)/var/lib/tor-arm/torrc
	# This is the only file that we expect members of our GROUP to be allowed to write into
	chmod 760 $(DESTDIR)/var/lib/tor-arm/torrc
	chown root:$(GROUP) $(DESTDIR)/var/lib/tor-arm/torrc
	
uninstall:
	deluser $(USER)
	delgroup $(GROUP)
	rm $(DESTDIR)/bin/tor-arm-replace-torrc
	rm $(DESTDIR)/bin/tor-arm-replace-torrc.py
	rm -r $(DESTDIR)/var/lib/tor-arm/
