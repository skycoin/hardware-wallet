# initialize from the image

FROM debian:9

ARG OS_NAME=linux
ENV OS_NAME=$OS_NAME

# install build tools and dependencies

ARG EMULATOR=0
ENV EMULATOR=$EMULATOR

RUN apt-get update && \
    apt-get install -y  \
    build-essential \
    curl \
    unzip \
    git \
    python3 \
    python3-pip \
    python-protobuf \
    wget \
    libusb-1.0.0-dev \
    cmake \
    udev \
    sudo

RUN python3 -m pip uninstall pip && \
    apt-get install python3-pip --reinstall

# download toolchain

ENV TOOLCHAIN_SHORTVER=6-2017q2
ENV TOOLCHAIN_LONGVER=gcc-arm-none-eabi-6-2017-q2-update
ENV TOOLCHAIN_URL=https://developer.arm.com/-/media/Files/downloads/gnu-rm/$TOOLCHAIN_SHORTVER/$TOOLCHAIN_LONGVER-$OS_NAME.tar.bz2

RUN if [ "$EMULATOR" = 1 ]; then \
        apt-get install -y libegl1-mesa-dev libgles2-mesa-dev libsdl2-dev libsdl2-image-dev; \
    fi

# extract toolchain

RUN cd /opt && wget $TOOLCHAIN_URL

RUN cd /opt && tar xfj $TOOLCHAIN_LONGVER-$OS_NAME.tar.bz2

# download protobuf

ENV PROTOBUF_VERSION=3.6.1
RUN wget "https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}/protoc-${PROTOBUF_VERSION}-linux-x86_64.zip"

ENV STLINK_VERSION=1.5.0
RUN wget "https://github.com/texane/stlink/archive/${STLINK_VERSION}.zip"

# setup toolchain

ENV PATH=/opt/$TOOLCHAIN_LONGVER/bin:$PATH

ENV PYTHON=python3
ENV PIP=pip3
ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

# use zipfile module to extract files world-readable
RUN $PYTHON -m zipfile -e "protoc-${PROTOBUF_VERSION}-linux-x86_64.zip" /usr/local && chmod 755 /usr/local/bin/protoc
RUN $PYTHON -m zipfile -e "1.5.0.zip" /tmp && \
    cd /tmp/stlink-1.5.0 && \
    make release && \
    cd build/Release && \
    make install && \
    ldconfig

#RUN udevadm control --reload-rules && udevadm trigger
RUN ldconfig

# install python dependencies

RUN printf "#!/usr/bin/python3\n\nimport sys\nfrom pip import __main__\n\nif __name__ == '__main__':\n    sys.exit(__main__._main())\n" > /usr/bin/pip3

RUN useradd -m user
USER user

RUN $PYTHON -m pip install --user pipenv
RUN $PYTHON -m pip install --user "protobuf==3.6.1" ecdsa
