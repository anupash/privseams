#!/bin/sh

TMPDIR=/tmp/subst-gpl
FROM='GNU\/GPL'
TO="MIT for InfraHIP industrial partners, for others GPL"
DIR=..
TMPFILE=temp

rm -rf $TMPDIR

set -e

mkdir $TMPDIR

for FILE in `find $DIR -name '*\.[c|h]'` 
do
  sed "s/$FROM/$TO/i" $FILE >$TMPDIR/$TMPFILE
  cp $TMPDIR/$TMPFILE $FILE
done
