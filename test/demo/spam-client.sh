#!/bin/sh

export PATH=$PATH:~mkomu/projects/hipl--spam--2.6/tools

PEER_NAME=panu
PEER_HIT=4014:ecbc:a9a:e3eb:32e7:51c1:c323:9ab5
PEER_IP=3ffe::3
SPAM_FILE=/usr/share/doc/spamassassin/examples/sample-spam.txt

die() {
    echo $1
    exit 1
}

grep $PEER_HIT /etc/hosts || die "Peer HIT ($PEER_HIT) must be in /etc/hosts"

for i in `seq 1 1` # `seq 10 30`
do
  hipconf add map $PEER_HIT $PEER_IP
  mailx root@${PEER_NAME} < ${SPAM_FILE}
done
