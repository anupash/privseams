#!/bin/sh

export PATH=$PATH:..

for K in `seq 1 40`
do
  LOGFILE="logs/cookieperf-${K}"
  rm -f $LOGFILE
  for REPEAT in `seq 1 30`
    do
    cookietest $K 2>&1|grep "puzzle solved"|tee -a $LOGFILE
  done
done