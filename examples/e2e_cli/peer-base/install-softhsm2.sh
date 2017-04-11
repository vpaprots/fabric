#!/bin/bash
set -e

ARCH=`uname -m`

if [ $ARCH = "s390x" ]; then
  echo "deb http://ftp.us.debian.org/debian sid main" >> /etc/apt/sources.list
fi

# Install softhsm2 package
apt-get update
apt-get -y install softhsm2 patch libtool

# Create tokens directory
mkdir -p /var/lib/softhsm/tokens/

for configFile in /etc/hyperledger/fabric/core.yaml /etc/hyperledger/fabric/orderer.yaml
do
	if [ ! -f $configFile ]
	then
		echo "INFO: $configFile not found to patch"
		continue
	fi
	
	patch $configFile << EOM
*** orig.txt	2017-04-06 18:20:08.000000000 -0400
--- new.txt	2017-04-06 18:20:10.000000000 -0400
***************
*** 1,8 ****
      # BCCSP (Blockchain crypto provider): Select which crypto implementation or
      # library to use
      BCCSP:
!         Default: SW
!         SW:
              # TODO: The default Hash and Security level needs refactoring to be
              # fully configurable. Changing these defaults requires coordination
              # SHA2 is hardcoded in several places, not only BCCSP
--- 1,12 ----
      # BCCSP (Blockchain crypto provider): Select which crypto implementation or
      # library to use
      BCCSP:
!         Default: PKCS11
!         PKCS11:
!             Library:
!             Label:
!             Pin:
! 
              # TODO: The default Hash and Security level needs refactoring to be
              # fully configurable. Changing these defaults requires coordination
              # SHA2 is hardcoded in several places, not only BCCSP
EOM
done