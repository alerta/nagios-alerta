SRC_MODULE=./src

all: get-deps nagios3

get-deps:
	sudo apt-get -y install libjansson-dev

nagios3:
	cd $(SRC_MODULE) && $(MAKE) nagios3

nagios4:
	cd $(SRC_MODULE) && $(MAKE) nagios4

install:
	cd $(SRC_MODULE) && $(MAKE) $@

test: nagios3 nagios4

clean:
	cd $(SRC_MODULE) && $(MAKE) $@
