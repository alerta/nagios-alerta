SRC_MODULE=./src

all:
	cd $(SRC_MODULE) && $(MAKE)

install:
	cd $(SRC_MODULE) && $(MAKE) $@

clean:
	cd $(SRC_MODULE) && $(MAKE) $@

