SRC_MODULE=./src

all: nagios4

nagios3:
	cd $(SRC_MODULE) && $(MAKE) nagios3

nagios4:
	cd $(SRC_MODULE) && $(MAKE) nagios4

install:
	cd $(SRC_MODULE) && $(MAKE) $@

clean:
	cd $(SRC_MODULE) && $(MAKE) $@

