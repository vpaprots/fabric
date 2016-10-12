#!/bin/bash

# ALERT: if you encounter an error like:
# error: [Errno 1] Operation not permitted: 'cf_update.egg-info/requires.txt'
# The proper fix is to remove any "root" owned directories under your update-cli directory
# as source mount-points only work for directories owned by the user running vagrant

# Stop on first error
set -e
set -x

# Update the entire system to the latest releases
apt-get update -qq
apt-get dist-upgrade -qqy
apt-get install --yes git netcat net-tools wget

MACHINE=`uname -m`
if [ x$MACHINE = xppc64le ]
then
   # install sudo
   apt-get install --yes sudo
fi

# Set Go environment variables needed by other scripts
export GOPATH="/opt/gopath"

#install golang
#apt-get install --yes golang
mkdir -p $GOPATH
if [ x$MACHINE = xs390x ]
then
   cd /tmp
   wget --quiet --no-check-certificate https://storage.googleapis.com/golang/go1.7.1.linux-s390x.tar.gz
   tar -xvf go1.7.1.linux-s390x.tar.gz
   apt-get install -y g++
   cd /opt
   git clone http://github.com/linux-on-ibm-z/go.git go
   cd go/src
   git checkout release-branch.go1.6-p256
   export GOROOT_BOOTSTRAP=/tmp/go
   ./make.bash
   rm -rf go1.7.1.linux-s390x.tar.gz /tmp/go
   export GOROOT="/opt/go"
elif [ x$MACHINE = xppc64le ]
then
   wget ftp://ftp.unicamp.br/pub/linuxpatch/toolchain/at/ubuntu/dists/trusty/at9.0/binary-ppc64el/advance-toolchain-at9.0-golang_9.0-3_ppc64el.deb
   dpkg -i advance-toolchain-at9.0-golang_9.0-3_ppc64el.deb
   rm advance-toolchain-at9.0-golang_9.0-3_ppc64el.deb

   update-alternatives --install /usr/bin/go go /usr/local/go/bin/go 9
   update-alternatives --install /usr/bin/gofmt gofmt /usr/local/go/bin/gofmt 9

   export GOROOT="/usr/local/go"
elif [ x$MACHINE = xx86_64 ]
then
   export GOROOT="/opt/go"

   #ARCH=`uname -m | sed 's|i686|386|' | sed 's|x86_64|amd64|'`
   ARCH=amd64
   GO_VER=1.6

   cd /tmp
   wget --quiet --no-check-certificate https://storage.googleapis.com/golang/go$GO_VER.linux-${ARCH}.tar.gz
   tar -xvf go$GO_VER.linux-${ARCH}.tar.gz
   mv go $GOROOT
   chmod 775 $GOROOT
   rm go$GO_VER.linux-${ARCH}.tar.gz
else
  echo "TODO: Add $MACHINE support"
  exit
fi

PATH=$GOROOT/bin:$GOPATH/bin:$PATH

cat <<EOF >/etc/profile.d/goroot.sh
export GOROOT=$GOROOT
export GOPATH=$GOPATH
export PATH=\$PATH:$GOROOT/bin:$GOPATH/bin
EOF

# ----------------------------------------------------------------
# Install JDK 1.8
# ----------------------------------------------------------------
if [ x$MACHINE = xs390x -o x$MACHINE = xppc64le ]
then
    # This 'installation' is ridiculous. Except this is the best I can come up with. Sad
    # Also, Java is required for node.bin below. InstallAnywhere requirement.
    # See https://github.com/ibmruntimes/ci.docker/blob/master/ibmjava/8-sdk/s390x/ubuntu/Dockerfile
    JAVA_VERSION=1.8.0_sr3fp12
    ESUM_s390x="46766ac01bc2b7d2f3814b6b1561e2d06c7d92862192b313af6e2f77ce86d849"
    ESUM_ppc64le="6fb86f2188562a56d4f5621a272e2cab1ec3d61a13b80dec9dc958e9568d9892"
    eval ESUM=\$ESUM_$MACHINE
    BASE_URL="https://public.dhe.ibm.com/ibmdl/export/pub/systems/cloud/runtimes/java/meta/"
    YML_FILE="sdk/linux/$MACHINE/index.yml"
    wget -q -U UA_IBM_JAVA_Docker -O /tmp/index.yml $BASE_URL/$YML_FILE
    JAVA_URL=$(cat /tmp/index.yml | sed -n '/'$JAVA_VERSION'/{n;p}' | sed -n 's/\s*uri:\s//p' | tr -d '\r')
    wget -q -U UA_IBM_JAVA_Docker -O /tmp/ibm-java.bin $JAVA_URL
    echo "$ESUM  /tmp/ibm-java.bin" | sha256sum -c -
    echo "INSTALLER_UI=silent" > /tmp/response.properties
    echo "USER_INSTALL_DIR=/opt/ibm/java" >> /tmp/response.properties
    echo "LICENSE_ACCEPTED=TRUE" >> /tmp/response.properties
    mkdir -p /opt/ibm
    chmod +x /tmp/ibm-java.bin
    /tmp/ibm-java.bin -i silent -f /tmp/response.properties
    rm -f /tmp/response.properties
    rm -f /tmp/index.yml
    rm -f /tmp/ibm-java.bin
    ln -s /opt/ibm/java/jre/bin/* /usr/local/bin/ 
fi

# Install NodeJS

if [ x$MACHINE = xs390x ]
then
    #apt-get install --yes nodejs
    
    # hack for debian
    # This 'installation' is ridiculous. Except this is the best I can come up with. Sad
    ESUM="9ff05558f6debd1f6d86cc1a0fd170cccb01b69d5cfd308faac57cd8246c14ba"
    NODE_URL="http://public.dhe.ibm.com/ibmdl/export/pub/systems/cloud/runtimes/nodejs/1.2.0.15/linux/s390x/ibm-1.2.0.15-node-v0.12.16-linux-s390x.bin"
    wget -O /tmp/node.bin $NODE_URL    
    echo "$ESUM  /tmp/node.bin" | sha256sum -c -
    echo "INSTALLER_UI=silent" > /tmp/response.properties
    echo "USER_INSTALL_DIR=/opt/ibm/node" >> /tmp/response.properties
    echo "LICENSE_ACCEPTED=TRUE" >> /tmp/response.properties
    mkdir -p /opt/ibm
    chmod +x /tmp/node.bin
    /tmp/node.bin -i silent -f /tmp/response.properties
    rm -f /tmp/response.properties /tmp/node.bin

elif [ x$MACHINE = xppc64le ]
then
    apt-get install --yes nodejs
else
    NODE_VER=0.12.7
    NODE_PACKAGE=node-v$NODE_VER-linux-x64.tar.gz
    TEMP_DIR=/tmp
    SRC_PATH=$TEMP_DIR/$NODE_PACKAGE

    # First remove any prior packages downloaded in case of failure
    cd $TEMP_DIR
    rm -f node*.tar.gz
    wget --quiet https://nodejs.org/dist/v$NODE_VER/$NODE_PACKAGE
    cd /usr/local && sudo tar --strip-components 1 -xzf $SRC_PATH
fi

# Install GRPC

# ----------------------------------------------------------------
# NOTE: For instructions, see https://github.com/google/protobuf
#
# ----------------------------------------------------------------

# First install protoc
cd /tmp
if [ x$MACHINE = xs390x ]
then
   git clone https://github.com/google/protobuf protobuf-3.0.2
   cd protobuf-3.0.2
   git checkout v3.0.2
   # missing attomic call
   git -c user.email="your@email.com" -c user.name="Your Name" cherry-pick fd1c289
else
   wget --quiet https://github.com/google/protobuf/archive/v3.0.2.tar.gz
   tar xpzf v3.0.2.tar.gz
   cd protobuf-3.0.2
fi
apt-get install -y autoconf automake libtool curl make g++ unzip
apt-get install -y build-essential
./autogen.sh
# NOTE: By default, the package will be installed to /usr/local. However, on many platforms, /usr/local/lib is not part of LD_LIBRARY_PATH.
# You can add it, but it may be easier to just install to /usr instead.
#
# To do this, invoke configure as follows:
#
# ./configure --prefix=/usr
#
#./configure
./configure --prefix=/usr
make
make check
make install
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
cd ~/

# Install rocksdb
apt-get install -y libsnappy-dev zlib1g-dev libbz2-dev
cd /tmp
git clone https://github.com/facebook/rocksdb.git
cd rocksdb
git checkout tags/v4.1
if [ x$MACHINE = xs390x ]
then
    echo There were some bugs in 4.1 for z/p, dev stream has the fix, living dangereously, fixing in place
    sed -i -e "s/-march=native/-march=z196/" build_tools/build_detect_platform
    sed -i -e "s/-momit-leaf-frame-pointer/-DDUMBDUMMY/" Makefile
elif [ x$MACHINE = xppc64le ]
then
    echo There were some bugs in 4.1 for z/p, dev stream has the fix, living dangereously, fixing in place.
    echo Below changes are not required for newer releases of rocksdb.
    sed -ibak 's/ifneq ($(MACHINE),ppc64)/ifeq (,$(findstring ppc64,$(MACHINE)))/g' Makefile
fi

PORTABLE=1 make shared_lib
INSTALL_PATH=/usr/local make install-shared
ldconfig
cd ~/

# Make our versioning persistent
echo $BASEIMAGE_RELEASE > /etc/hyperledger-baseimage-release

# clean up our environment
apt-get -y autoremove
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
