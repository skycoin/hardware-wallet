DATA=$(wildcard *.dat)

all: devicerandom osrandom osurandom dieharder ent rngtest ## Generate random buffers from host device and harware-wallet, run tests over those buffers
	for i in `seq 8` ; do skycoin-hw-cli getEntropy --outFile stm32_rng_$$i.dat --entropyBytes 10; done

devicerandom:
	 for i in `seq 8` ; do skycoin-hw-cli getEntropy --outFile stm32_rng_$$i.dat --entropyBytes 10; done

osrandom:
	for i in `seq 4`; do dd if=/dev/random bs=64K count=1 of=dev_random_$$i.dat iflag=fullblock; done

osurandom:
	for i in `seq 8`; do dd if=/dev/urandom bs=1M count=1 of=dev_urandom_$$i.dat iflag=fullblock; done

dieharder: $(DATA:%.dat=%.dieharder)

ent: $(DATA:%.dat=%.ent)

rngtest: $(DATA:%.dat=%.rngtest)

%.dieharder: %.dat
	dieharder -a -f $< > $@

%.ent: %.dat
	ent $< > $@

%.rngtest: %.dat
	cat $< | rngtest 2> $@ || true
