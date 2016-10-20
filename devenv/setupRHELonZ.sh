#!/bin/bash

# Development on Z is done on the native OS, not in Vagrant. This script can be 
# used to set things up in RHEL on Z, similar to devenv/setup.sh which does the 
# same for Vagrant. 
# See https://github.com/hyperledger/fabric/blob/master/docs/dev-setup/install.md
#
# To get started:
#       sudo su
#       yum install git
#       mkdir -p $HOME/git/src/github.com/hyperledger
#       cd $HOME/git/src/github.com/hyperledger
#       git clone http://gerrit.hyperledger.org/r/fabric
#       source fabric/devenv/setupRHELonZ.sh
#       make peer unit-test behave

if [ xroot != x$(whoami) ]
then
   echo "You must run as root (Hint: sudo su)"
   exit
fi

if [ -n -d $HOME/git/src/github.com/hyperledger/fabric ]
then
    echo "Script fabric code is under $HOME/git/src/github.com/hyperledger/fabric "
    exit
fi

#TODO: should really just open a few ports..
iptables -I INPUT 1 -j ACCEPT
sysctl vm.overcommit_memory=1

##################
# Install Docker
cd /tmp
wget ftp://ftp.unicamp.br/pub/linuxpatch/s390x/redhat/rhel7.2/docker-1.11.2-rhel7.2-20160623.tar.gz
tar -xvzf docker-1.11.2-rhel7.2-20160623.tar.gz
cp docker-1.11.2-rhel7.2-20160623/docker* /bin
rm -rf docker-1.11.2-rhel7.2-20160623 docker-1.11.2-rhel7.2-20160623.tar.gz

#TODO: Install on boot
nohup docker daemon -g /data/docker -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock 2>&1 >/dev/null&

###################################
# Crosscompile and install GOLANG
cd /tmp
wget --quiet --no-check-certificate https://storage.googleapis.com/golang/go1.7.1.linux-s390x.tar.gz
tar -xvf go1.7.1.linux-s390x.tar.gz
#apt-get install -y g++
cd /opt
git clone http://github.com/linux-on-ibm-z/go.git go
cd go/src
git checkout release-branch.go1.6-p256
export GOROOT_BOOTSTRAP=/tmp/go
./make.bash
rm -rf go1.7.1.linux-s390x.tar.gz /tmp/go
export GOROOT="/opt/go"

export PATH=/opt/go/bin:/root/git/bin:$PATH

# ----------------------------------------------------------------
# Install JDK 1.8
# ----------------------------------------------------------------
# This 'installation' is ridiculous. Except this is the best I can come up with. Sad
# Also, Java is required for node.bin below. InstallAnywhere requirement.
# See https://github.com/ibmruntimes/ci.docker/blob/master/ibmjava/8-sdk/s390x/ubuntu/Dockerfile
export JAVA_VERSION=1.8.0_sr3fp12
export ESUM="46766ac01bc2b7d2f3814b6b1561e2d06c7d92862192b313af6e2f77ce86d849"
export BASE_URL="https://public.dhe.ibm.com/ibmdl/export/pub/systems/cloud/runtimes/java/meta/"
export YML_FILE="sdk/linux/s390x/index.yml"
wget -q -U UA_IBM_JAVA_Docker -O /tmp/index.yml $BASE_URL/$YML_FILE
export JAVA_URL=`cat /tmp/index.yml | sed -n '/'$JAVA_VERSION'/{n;p}' | sed -n 's/\s*uri:\s//p' | tr -d '\r'`
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
export PATH=/opt/ibm/java/jre/bin:$PATH

# Install NodeJS
# This 'installation' is ridiculous. Except this is the best I can come up with. Sad
export ESUM="9ff05558f6debd1f6d86cc1a0fd170cccb01b69d5cfd308faac57cd8246c14ba"
export NODE_URL="http://public.dhe.ibm.com/ibmdl/export/pub/systems/cloud/runtimes/nodejs/1.2.0.15/linux/s390x/ibm-1.2.0.15-node-v0.12.16-linux-s390x.bin"
wget -O /tmp/node.bin $NODE_URL    
echo "$ESUM  /tmp/node.bin" | sha256sum -c -
echo "INSTALLER_UI=silent" > /tmp/response.properties
echo "USER_INSTALL_DIR=/opt/ibm/node" >> /tmp/response.properties
echo "LICENSE_ACCEPTED=TRUE" >> /tmp/response.properties
mkdir -p /opt/ibm
chmod +x /tmp/node.bin
/tmp/node.bin -i silent -f /tmp/response.properties
rm -f /tmp/response.properties /tmp/node.bin
export PATH=/opt/ibm/node/bin:$PATH

# Install GRPC

# ----------------------------------------------------------------
# NOTE: For instructions, see https://github.com/google/protobuf
#
# ----------------------------------------------------------------

# First install protoc
cd /tmp
git clone https://github.com/google/protobuf protobuf-3.0.2
cd protobuf-3.0.2
git checkout v3.0.2
# missing attomic call
git -c user.email="your@email.com" -c user.name="Your Name" cherry-pick fd1c289
yum install -y autoconf automake libtool curl make g++ unzip build-essential
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

################
#ROCKSDB BUILD

cd /tmp
yum install -y gcc-c++ snappy snappy-devel zlib zlib-devel bzip2 bzip2-devel
git clone https://github.com/facebook/rocksdb.git
cd  rocksdb
git checkout tags/v4.1
echo There were some bugs in 4.1 for x/p, dev stream has the fix, living dangereously, fixing in place
sed -i -e "s/-march=native/-march=zEC12/" build_tools/build_detect_platform
sed -i -e "s/-momit-leaf-frame-pointer/-DDUMBDUMMY/" Makefile
make shared_lib && INSTALL_PATH=/usr make install-shared && ldconfig
cd /tmp
rm -rf /tmp/rocksdb

################
# PIP
yum install python-setuptools
curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"
python get-pip.py
pip install --upgrade pip
pip install behave nose docker-compose

################
#grpcio package

git clone https://github.com/grpc/grpc.git
cd grpc
pip install -rrequirements.txt
git checkout tags/release-0_13_1
sed -i -e "s/boringssl.googlesource.com/github.com\/linux-on-ibm-z/" .gitmodules
git submodule sync
git submodule update --init
cd third_party/boringssl
git checkout s390x-big-endian
cd ../..
GRPC_PYTHON_BUILD_WITH_CYTHON=1 pip install .

# updater-server, update-engine, and update-service-common dependencies (for running locally)
pip install -I flask==0.10.1 python-dateutil==2.2 pytz==2014.3 pyyaml==3.10 couchdb==1.0 flask-cors==2.0.1 requests==2.4.3 docker-compose==1.5.2
cat >> ~/.bashrc <<HEREDOC
export PATH=$PATH
export GOROOT=$HOME/go
export GOPATH=$HOME/git
HEREDOC

source ~/.bashrc

# Build the actual hyperledger peer
cd $GOPATH/src/github.com/hyperledger/fabric
make clean peer
