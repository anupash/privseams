#!/bin/sh
# useful for debugging: -xv

HIPL_DIR=~/dev/hipl--esp--2.6
BASE_DIR=~/dev/measurements
DEVICE_TYPE=endhost

# needed by the script - don't change these variables
EXT_BASE_DIR=$BASE_DIR/auth_performance2
TEST_DIR=$HIPL_DIR/test
OUTPUT_DIR=$EXT_BASE_DIR/output
STAGING_DIR=$EXT_BASE_DIR/staging
RESULTS_DIR=$EXT_BASE_DIR/results


if [ ! -e $BASE_DIR ]
then
  echo $BASE_DIR "not found"
  exit 1
fi

if [ ! -e $EXT_BASE_DIR ]
then
  echo $EXT_BASE_DIR "not found"
  exit 1
fi

if [ ! -e $OUTPUT_DIR ]
then
  echo $OUTPUT_DIR "not found"
  exit 1
fi

if [ ! -e $OUTPUT_DIR/$DEVICE_TYPE ]
then
  echo $OUTPUT_DIR/$DEVICE_TYPE "not found"
  exit 1
fi

if [ ! -e $STAGING_DIR ]
then
  mkdir $STAGING_DIR
fi

if [ ! -e $STAGING_DIR/$DEVICE_TYPE ]
then
  mkdir $STAGING_DIR/$DEVICE_TYPE
fi

if [ ! -e $RESULTS_DIR ]
then
  mkdir $RESULTS_DIR
fi

if [ ! -e $RESULTS_DIR/$DEVICE_TYPE ]
then
  mkdir $RESULTS_DIR/$DEVICE_TYPE
fi

cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "sha1-20:") printf("%.3f ms\n", $3);}' | tee $STAGING_DIR/$DEVICE_TYPE/sha1-20
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "sha1-40:") printf("%.3f ms\n", $3);}' | tee $STAGING_DIR/$DEVICE_TYPE/sha1-40
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "sha1-1280:") printf("%.3f ms\n", $3);}' | tee $STAGING_DIR/$DEVICE_TYPE/sha1-1280
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "sha1-hmac:") printf("%.3f ms\n", $3);}' | tee $STAGING_DIR/$DEVICE_TYPE/sha1-hmac
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "AES" && $3 == "encrypt:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/aes_enc
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "AES" && $3 == "decrypt:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/aes_dec
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "rsa" && $3 == "signature:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/rsa_sign
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "rsa" && $3 == "verification:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/rsa_verify
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "dsa" && $3 == "signature:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/dsa_sign
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "dsa" && $3 == "verification:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/dsa_verify
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "ecdsa" && $3 == "signature:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/ecdsa_sign
cat $OUTPUT_DIR/$DEVICE_TYPE | awk '{if ($2 == "ecdsa" && $3 == "verification:") printf("%.3f ms\n", $4);}' | tee $STAGING_DIR/$DEVICE_TYPE/ecdsa_verify

cat $STAGING_DIR/$DEVICE_TYPE/sha1-20 | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/sha1-20
cat $STAGING_DIR/$DEVICE_TYPE/sha1-40 | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/sha1-40
cat $STAGING_DIR/$DEVICE_TYPE/sha1-1280 | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/sha1-1280
cat $STAGING_DIR/$DEVICE_TYPE/sha1-hmac | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/sha1-hmac
cat $STAGING_DIR/$DEVICE_TYPE/aes_enc | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/aes_enc
cat $STAGING_DIR/$DEVICE_TYPE/aes_dec | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/aes_dec
cat $STAGING_DIR/$DEVICE_TYPE/rsa_sign | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/rsa_sign
cat $STAGING_DIR/$DEVICE_TYPE/rsa_verify | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/rsa_verify
cat $STAGING_DIR/$DEVICE_TYPE/dsa_sign | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/dsa_sign
cat $STAGING_DIR/$DEVICE_TYPE/dsa_verify | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/dsa_verify
cat $STAGING_DIR/$DEVICE_TYPE/ecdsa_sign | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/ecdsa_sign
cat $STAGING_DIR/$DEVICE_TYPE/ecdsa_verify | $TEST_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\tper_sec\n"); printf("%.3f\t%.3f\t%.3f\n", $2, $3, 1000/$2);}}' | tee $RESULTS_DIR/$DEVICE_TYPE/ecdsa_verify
