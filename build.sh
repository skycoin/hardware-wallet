git submodule update --init --remote --recursive
make clean
docker build -t skywallet .
docker run --rm -it -v $(pwd):/hardware-wallet:Z -w /hardware-wallet skywallet make full-firmware
