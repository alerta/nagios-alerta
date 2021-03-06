SRC_MODULE=./src

.DEFAULT_GOAL=help

lint:
	indent -i2 -di1 -br -nut -pcs -l160 -bls $(SRC_MODULE)/alerta-neb.c

get-deps:
	apt-get -y install libjansson-dev

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

help:
	@echo "Nagios NEB Module"
