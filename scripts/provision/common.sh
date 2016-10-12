#!/bin/bash

# Add any logic that is common to both the peer and docker environments here

apt-get update -qq

# Used by CHAINTOOL
if [ x$MACHINE = xs390x -o x$MACHINE = xppc64le ]
then
   : #already installed in common/setup.sh
else
    apt-get install -y default-jre
fi
