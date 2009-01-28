#!/bin/sh -xv

LAST_PATCH=""

for i in `baz missing hipl--userspace--2.6`
  do
  test xhipl-dev@freelists.org--hipl/${1} = x${i} && break
  echo "*** Replay $i ***"
  baz replay $i
  test $? -ne 0 && break
  LAST_PATCH=$i
done

echo "baz commit -s 'Synchronized to $LAST_PATCH'"
