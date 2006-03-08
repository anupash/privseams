#!/bin/sh

export PATH=$PATH:.

for K in `seq 1 30`
do
  stats.pl 95 type '.*(puzzle)\s+solved\s+in\s+(\S+)\s*' <logs/cookieperf-${K} | tail -1 >logs/cookieperf-final-${K}
done