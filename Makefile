SHELL=/bin/bash

#PREFIX: where things are installed
PREFIX=/opt/smartpot

all:
	chmod +x install.sh
	sudo ./install.sh "$(PREFIX)"

distclean:
	chmod +x clean.sh
	sudo ./clean.sh "$(PREFIX)"
