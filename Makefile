#
# lard makefile
#

VERSION = `perl lard -v`

all:

install: man
	install -m755 lard /usr/sbin
	if [ ! -e /etc/lard.conf ]; then
		install -m644 lard.conf /etc/
	fi
	install -m644 lard.8 /usr/share/man/man8/
	install -m644 lard.conf.5 /usr/share/man/man5/

man:
	pod2man lard lard.8
	pod2man lard.conf.pod lard.conf.5

clean:
	rm lard.8 lard.conf.5

dist: man
	mkdir lard-$(VERSION)
	cp lard lard.conf Makefile lard.8 lard.conf.5 lard.conf.pod lard-$(VERSION)/
	tar cjf lard-$(VERSION).tar.bz2 lard-$(VERSION)/
	rm -rf lard-$(VERSION)
