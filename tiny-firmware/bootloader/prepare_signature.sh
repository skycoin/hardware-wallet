make -C ../../skycoin-crypto clean
make -C ../../skycoin-crypto libskycoin-crypto.so
cp ../../skycoin-crypto/libskycoin-crypto.so .
make -C ../../skycoin-crypto clean
ln -sf ../../skycoin-crypto/skycoin_crypto.py .
