SRC_MODULE=./src

all: get-deps

get-deps:
	sudo apt-get -y install libjansson-dev

nagios3:
	cd $(SRC_MODULE) && $(MAKE) nagios3

nagios4:
	cd $(SRC_MODULE) && $(MAKE) nagios4

naemon:
	cd $(SRC_MODULE) && $(MAKE) naemon

install:
	cd $(SRC_MODULE) && $(MAKE) $@

test: nagios3 nagios4 naemon

clean:
	cd $(SRC_MODULE) && $(MAKE) $@
