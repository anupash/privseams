#!/bin/sh
# useful for debugging: -xv

HIPL_DIR=~/dev/hipl--esp--2.6
BASE_DIR=~/dev/measurements
MB_TYPE=test

# needed by the script - don't change these variables
TEST_DIR=$HIPL_DIR/test
OUTPUT_DIR=$BASE_DIR/output

if [ ! -e $BASE_DIR ]
then
  mkdir $BASE_DIR
fi

if [ ! -e $OUTPUT_DIR ]
then
  mkdir $OUTPUT_DIR
fi


$TEST_DIR/auth_performance | tee $OUTPUT_DIR/$MB_TYPE
