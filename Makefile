#
# lard makefile
#

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
