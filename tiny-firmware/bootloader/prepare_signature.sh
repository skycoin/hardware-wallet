make -C ../../skycoin-api clean
make -C ../../skycoin-api libskycoin-crypto.so
cp ../../skycoin-api/libskycoin-crypto.so .
make -C ../../skycoin-api clean
ln -sf ../../skycoin-api/skycoin_crypto.py .