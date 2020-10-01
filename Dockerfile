FROM debian:9

ARG OS_NAME=linux
ENV OS_NAME=$OS_NAME

# install build tools and dependencies

RUN apt-get update && \
    apt-get install -y  \
    libpython2.7-minimal=2.7.13-2+deb9u4 \
    libkmod2=23-2 \
    python2.7-minimal=2.7.13-2+deb9u4 \
    libncurses5=6.0+20161126-1+deb9u2 \
    libprocps6=2:3.3.12-3+deb9u1 \
    procps=2:3.3.12-3+deb9u1 \
    udev=232-25+deb9u12 \
    perl-modules-5.24=5.24.1-3+deb9u7 \
    libsqlite3-0=3.16.2-5+deb9u2 \
    libpython2.7-stdlib=2.7.13-2+deb9u4 \
    libgdbm3=1.8.3-14 \
    libperl5.24=5.24.1-3+deb9u7 \
    python2.7=2.7.13-2+deb9u4 \
    libxml2=2.9.4+dfsg1-2.2+deb9u3 \
    libcurl3=7.52.1-5+deb9u11 \
    libcurl3-gnutls=7.52.1-5+deb9u11 \
    libpython3.5-minimal=3.5.3-1+deb9u2 \
    perl=5.24.1-3+deb9u7 \
    python3.5-minimal=3.5.3-1+deb9u2 \
    python-minimal=2.7.13-2 \
    mime-support=3.60 \
    libexpat1=2.2.0-2+deb9u3 \
    libffi6=3.2.1-6 \
    readline-common=7.0-3 \
    libreadline7=7.0-3 \
    libssl1.1=1.1.0l-1~deb9u1 \
    libpython3.5-stdlib=3.5.3-1+deb9u2 \
    libpython-stdlib=2.7.13-2 \
    python=2.7.13-2 \
    cmake-data=3.7.2-1 \
    liblzo2-2=2.08-1.2+b2 \
    libicu57=57.1-6+deb9u4 \
    python3.5=3.5.3-1+deb9u2 \
    curl=7.52.1-5+deb9u11 \
    libpython3.5=3.5.3-1+deb9u2 \
    libpython3.5-dev=3.5.3-1+deb9u2 \
    libarchive13=3.2.2-2+deb9u2 \
    libkeyutils1=1.5.9-9 \
    libkrb5support0=1.15-1+deb9u1 \
    libk5crypto3=1.15-1+deb9u1 \
    libkrb5-3=1.15-1+deb9u1 \
    libgssapi-krb5-2=1.15-1+deb9u1 \
    libunistring0=0.9.6+really0.9.3-0.1 \
    libidn2-0=0.16-1+deb9u1 \
    libgmp10=2:6.1.2+dfsg-1 \
    libhogweed4=3.3-1+b2 \
    libp11-kit0=0.23.3-2 \
    libtasn1-6=4.10-1.1+deb9u1 \
    libgnutls30=3.5.8-5+deb9u5 \
    libsasl2-modules-db=2.1.27~101-g0780600+dfsg-3+deb9u1 \
    libsasl2-2=2.1.27~101-g0780600+dfsg-3+deb9u1 \
    libldap-common=2.4.44+dfsg-5+deb9u4 \
    libldap-2.4-2=2.4.44+dfsg-5+deb9u4 \
    libnghttp2-14=1.18.1-1+deb9u1 \
    libpsl5=0.17.0-3 \
    librtmp1=2.4+20151223.gitfa8646d.1-1+b1 \
    libssh2-1=1.7.0-1+deb9u1 \
    libssl1.0.2=1.0.2u-1~deb9u1 \
    libjsoncpp1=1.7.4-3 \
    libuv1=1.9.1-3 \
    cmake=3.7.2-1 \
    liberror-perl=0.17024-1 \
    git-man=1:2.11.0-3+deb9u7 \
    git=1:2.11.0-3+deb9u7 \
    liblocale-gettext-perl=1.07-3+b1 \
    libxau6=1:1.0.8-1 \
    python3-minimal=3.5.3-1 \
    libmpdec2=2.4.2-1 \
    libpython3-stdlib=3.5.3-1 \
    dh-python=2.20170125 \
    python3=3.5.3-1 \
    sgml-base=1.29 \
    libassuan0=2.4.3-2 \
    pinentry-curses=1.0.0-2 \
    libnpth0=1.3-1 \
    gnupg-agent=2.1.18-8~deb9u4 \
    libksba8=1.3.5-2 \
    gnupg=2.1.18-8~deb9u4 \
    libpopt0=1.16-10+b2 \
    netbase=5.4 \
    wget=1.18-5+deb9u3 \
    bzip2=1.0.6-8.1 \
    libapparmor1=2.11.0-3+deb9u2 \
    libdbus-1-3=1.10.32-0+deb9u1 \
    dbus=1.10.32-0+deb9u1 \
    libmagic-mgc=1:5.30-1+deb9u3 \
    libmagic1=1:5.30-1+deb9u3 \
    file=1:5.30-1+deb9u3 \
    krb5-locales=1.15-1+deb9u1 \
    less=481-2.1 \
    libbsd0=0.8.3-1 \
    libedit2=3.1-20160903-3 \
    libgpm2=1.20.4-6.2+b1 \
    manpages=4.10-2 \
    openssh-client=1:7.4p1-10+deb9u7 \
    xz-utils=5.2.2-1.2+b1 \
    binutils=2.28-5 \
    libc-dev-bin=2.24-11+deb9u4 \
    linux-libc-dev=4.9.228-1 \
    libc6-dev=2.24-11+deb9u4 \
    libisl15=0.18-1 \
    libmpfr4=3.1.5-1 \
    libmpc3=1.0.3-1+b2 \
    cpp-6=6.3.0-18+deb9u1 \
    cpp=4:6.3.0-4 \
    libcc1-0=6.3.0-18+deb9u1 \
    libgomp1=6.3.0-18+deb9u1 \
    libitm1=6.3.0-18+deb9u1 \
    libatomic1=6.3.0-18+deb9u1 \
    libasan3=6.3.0-18+deb9u1 \
    liblsan0=6.3.0-18+deb9u1 \
    libtsan0=6.3.0-18+deb9u1 \
    libubsan0=6.3.0-18+deb9u1 \
    libcilkrts5=6.3.0-18+deb9u1 \
    libmpx2=6.3.0-18+deb9u1 \
    libquadmath0=6.3.0-18+deb9u1 \
    libgcc-6-dev=6.3.0-18+deb9u1 \
    gcc-6=6.3.0-18+deb9u1 \
    libx11-data=2:1.6.4-3+deb9u3 \
    gcc=4:6.3.0-4 \
    libstdc++-6-dev=6.3.0-18+deb9u1 \
    libx11-6=2:1.6.4-3+deb9u3 \
    python-pip-whl=9.0.1-2+deb9u2 \
    g++-6=6.3.0-18+deb9u1 \
    python3.5-dev=3.5.3-1+deb9u2 \
    python3-pip=9.0.1-2+deb9u2 \
    g++=4:6.3.0-4 \
    make=4.1-9.1 \
    libdpkg-perl=1.18.25 \
    patch=2.7.5-1+deb9u2 \
    dpkg-dev=1.18.25 \
    build-essential=12.3 \
    openssl=1.1.0l-1~deb9u1 \
    ca-certificates=20200601~deb9u1 \
    dirmngr=2.1.18-8~deb9u4 \
    libfakeroot=1.21-3.1 \
    fakeroot=1.21-3.1 \
    libglib2.0-0=2.50.3-2+deb9u2 \
    libgirepository-1.0-1=1.50.0-1+b1 \
    gir1.2-glib-2.0=1.50.0-1+b1 \
    libalgorithm-diff-perl=1.19.03-1 \
    libalgorithm-diff-xs-perl=0.04-4+b2 \
    libalgorithm-merge-perl=0.08-3 \
    libdbus-glib-1-2=0.108-2 \
    libexpat1-dev=2.2.0-2+deb9u3 \
    libfile-fcntllock-perl=0.22-3+b2 \
    libglib2.0-data=2.50.3-2+deb9u2 \
    libprotobuf10=3.0.0-9 \
    libpython3-dev=3.5.3-1 \
    libsasl2-modules=2.1.27~101-g0780600+dfsg-3+deb9u1 \
    libusb-1.0-0=2:1.0.21-1 \
    libusb-1.0-0-dev=2:1.0.21-1 \
    libusb-1.0-doc=2:1.0.21-1 \
    libxdmcp6=1:1.1.2-3 \
    libxcb1=1.12-1 \
    libxext6=2:1.3.3-1+b2 \
    libxmuu1=2:1.1.2-2 \
    manpages-dev=4.10-2 \
    psmisc=22.21-2.1+b2 \
    python-pkg-resources=33.1.1-1 \
    python-six=1.10.0-3 \
    python-protobuf=3.0.0-9 \
    python3-cffi-backend=1.9.1-2 \
    python3-crypto=2.6.1-7 \
    python3-idna=2.2-1 \
    python3-pyasn1=0.1.9-2 \
    python3-pkg-resources=33.1.1-1 \
    python3-setuptools=33.1.1-1 \
    python3-six=1.10.0-3 \
    python3-cryptography=1.7.1-3+deb9u2 \
    python3-dbus=1.2.4-1+b1 \
    python3-dev=3.5.3-1 \
    python3-gi=3.22.0-2 \
    python3-secretstorage=2.3.1-2 \
    python3-keyring=10.1-1 \
    python3-keyrings.alt=1.3-1 \
    python3-wheel=0.29.0-2 \
    python3-xdg=0.25-4 \
    rename=0.20-4 \
    rsync=3.1.2-1+deb9u2 \
    shared-mime-info=1.8-1+deb9u1 \
    sudo=1.8.19p1-2.1+deb9u2 \
    unzip=6.0-21+deb9u2 \
    xauth=1:1.0.9-1+b2 \
    xdg-user-dirs=0.15-2+b1 \
    xml-core=0.17 \
    gnupg-l10n=2.1.18-8~deb9u4 \
    publicsuffix=20190415.1030-0+deb9u1

# download toolchain

ENV TOOLCHAIN_SHORTVER=6-2017q2
ENV TOOLCHAIN_LONGVER=gcc-arm-none-eabi-6-2017-q2-update
ENV TOOLCHAIN_URL=https://developer.arm.com/-/media/Files/downloads/gnu-rm/$TOOLCHAIN_SHORTVER/$TOOLCHAIN_LONGVER-$OS_NAME.tar.bz2

# extract toolchain

RUN cd /opt && \
    wget $TOOLCHAIN_URL && \
    tar xfj $TOOLCHAIN_LONGVER-$OS_NAME.tar.bz2

# download protobuf

ENV PROTOBUF_VERSION=3.6.1
RUN wget "https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}/protoc-${PROTOBUF_VERSION}-linux-x86_64.zip"

ENV STLINK_VERSION=1.5.0
RUN wget "https://github.com/texane/stlink/archive/v${STLINK_VERSION}.zip"

# setup toolchain

ENV PATH=/opt/$TOOLCHAIN_LONGVER/bin:$PATH

ENV PYTHON=python3
ENV PIP=pip3
ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# use zipfile module to extract files world-readable
RUN $PYTHON -m zipfile -e "protoc-${PROTOBUF_VERSION}-linux-x86_64.zip" /usr/local && \
    chmod 755 /usr/local/bin/protoc
RUN $PYTHON -m zipfile -e "v1.5.0.zip" /tmp && \
    cd /tmp/stlink-1.5.0 && \
    make release && \
    cd build/Release && \
    make install && \
    ldconfig

RUN useradd -m user
USER user

RUN $PYTHON -m pip install --user "protobuf==3.6.1" "ecdsa==0.16.0" "setuptools==49.6.0"
