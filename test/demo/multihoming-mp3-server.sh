#!/bin/sh

# REMEMBER TO STOP VMWARE

HIPL_DIR=$1
PORT=12345
MP3="/home/mkousa/m/Scott_Mckenzie-San_Francisco.mp3"
AVI="/home/mkousa/julmahuvi3.avi"
PEER_IP0=fe80::204:76ff:fe4c:5176
PEER_IP1=fe80::200:86ff:fe57:7dd
PEER_MAC0=00:04:76:4c:51:76
PEER_MAC1=00:00:86:57:07:dd

if [ "$HIPL_DIR" = "" ]
then
    echo "usage: $0 HIPL_DIR"
    exit 1
fi

killall ifd
sleep 2

killall hipd
sleep 2
rmmod hipmod
sleep 2

set -e

insmod hipmod
sleep 2

cd $HIPL_DIR
hipd/hipd&
sleep 2

echo "Starting server"

#nc6 -n -vv -l -p $PORT --sndbuf-size=1000 < $MP3
#nc6 -n -vv -l -p $PORT < $MP3
#$HIPL_DIR/test/demo/stdinserver tcp $PORT < $AVI 
nc6 -n -vv -l -p $PORT < $AVI 
