DATA=$(wildcard *.dat)

trng-generate-buffers: devicerandom osrandom osurandom ## Generate random buffers from host device and harware-wallet

run-tests: dieharder ent rngtest ## Run tests over those buffers

devicerandom:
	 for i in `seq 8` ; do skycoin-hw-cli getRawEntropy --outFile stm32_rng_raw_$$i.dat --entropyBytes 1048576; skycoin-hw-cli getMixedEntropy --outFile stm32_rng_mixed_$$i.dat --entropyBytes 1048576; done

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

clean:
	rm -rf *.dat
	rm -rf *.ent
	rm -rf *.rngtest
	rm -rf *.dieharder
