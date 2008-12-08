#!/bin/bash
# useful for debugging: -xv

BASE_DIR=~/dev/measurements
HIPL_DIR=~/dev/hipl--esp--2.6

# needed by the script - don't change these variables
STATS_DIR=$HIPL_DIR/test/performance
EXT_BASE_DIR=$BASE_DIR
OUTPUT_DIR=output
STAGING_DIR=staging
RESULTS_DIR=results


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

if [ ! -e  $OUTPUT_DIR ]
then
  mkdir $OUTPUT_DIR
fi

if [ ! -e $STAGING_DIR ]
then
  mkdir $STAGING_DIR
fi

if [ ! -e $RESULTS_DIR ]
then
  mkdir $RESULTS_DIR
fi

if [ ! -e $PLOT_DATA_DIR ]
then
  mkdir $PLOT_DATA_DIR
fi

# RTT output post-processing
grep 'from' $OUTPUT_DIR/$FILE | tr '=' ' ' | $STATS_DIR/stats.pl 95 type '(time)\s+(\S+)' | tee $STAGING_DIR/$FILE
grep 'time' $STAGING_DIR/$FILE | awk '{printf("#avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}' | tee $RESULTS_DIR/$FILE
# symlink newest results to plot_data dir
ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

# TCP output post-processing
grep 'sec' $OUTPUT_DIR/$FILE | awk '{printf("Mbits/sec "); printf("%.3f\n", $7)}' | $STATS_DIR/stats.pl 95 type '(Mbits/sec)\s+(\S+)' | tee $STAGING_DIR/$FILE
grep 'Mbits/sec' $STAGING_DIR/$FILE | awk '{printf("#avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}' | tee $RESULTS_DIR/$FILE
# symlink newest results to plot_data dir
ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

# UDP output post-processing
grep '%' $OUTPUT_DIR/$FILE | awk '{printf("Mbits/sec "); printf("%.3f\n", $7)}' | $STATS_DIR/stats.pl 95 type '(Mbits/sec)\s+(\S+)' | tee $STAGING_DIR/$FILE
grep 'Mbits/sec' $STAGING_DIR/$FILE | awk '{printf("#avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}' | tee $RESULTS_DIR/$FILE
# symlink newest results to plot_data dir
ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

#if [ $DO_PLOT -eq "1" ]
#then
#  read -p "Plot histograms: [ENTER]"
#  TMP_DIR=`pwd`
#  cd $BASE_DIR
#  gnuplot $STATS_DIR/plot-no_midfw
#  gnuplot $STATS_DIR/plot-with_pcfw
#  cd $TMP_DIR
#fi

