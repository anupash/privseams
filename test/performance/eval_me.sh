#!/bin/bash
# useful for debugging: -xv

BASE_DIR=~/dev/measurements
HIPL_DIR=~/dev/hipl--esp--2.6
#LEVEL_1_DIRS=no_mb router corp_fw pc_fw
#LEVEL_2_DIRS=rtt-no_load rtt-with_load tcp udp

# needed by the script - don't change these variables
STATS_DIR=$HIPL_DIR/test/performance
EXT_BASE_DIR=$BASE_DIR/networking
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

for dir_level_1 in $EXT_BASE_DIR/*
do
  for dir_level_2 in $dir_level_1/*
  do

        if [ -e $dir_level_2/$OUTPUT_DIR ]
        then
      
          if [ ! -e $dir_level_2/$STAGING_DIR ]
          then
            mkdir $dir_level_2/$STAGING_DIR
          fi

          if [ ! -e $dir_level_2/$RESULTS_DIR ]
          then
            mkdir $dir_level_2/$RESULTS_DIR
          fi

          # do post-processing
          for file_name in $dir_level_2/$OUTPUT_DIR/*
          do
            
            file_name=`basename $file_name` 

            if [ $dir_level_2 == $dir_level_1/rtt-no_load -o $dir_level_2 == $dir_level_1/rtt-with_load ]
            then
              # RTT output post-processing
              grep 'from' $dir_level_2/$OUTPUT_DIR/$file_name | tr '=' ' ' | awk '{printf("%.3f ms\n", $10)}' | tee $dir_level_2/$STAGING_DIR/$file_name | $STATS_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}}' | tee $dir_level_2/$RESULTS_DIR/$file_name
              # symlink newest results to plot_data dir
              #ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

            elif [ $dir_level_2 == $dir_level_1/tcp ]
            then
              # TCP output post-processing
              grep 'sec' $dir_level_2/$OUTPUT_DIR/$file_name | awk '{printf("%.3f Mbits/sec\n", $7)}' | tee $dir_level_2/$STAGING_DIR/$file_name | $STATS_DIR/stats.pl 95 value '(\S+)\s+(Mbits/sec)' | awk '{if ($1 == "Mbits/sec") {printf("avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}}' | tee $dir_level_2/$RESULTS_DIR/$file_name
              # symlink newest results to plot_data dir
              #ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

            elif [ $dir_level_2 == $dir_level_1/udp ]
            then
              # UDP output post-processing
              #echo "udp" $file_name
              grep '%' $dir_level_2/$OUTPUT_DIR/$file_name | awk '{printf("%.3f Mbits/sec\n", $7)}' | tee $dir_level_2/$STAGING_DIR/$file_name | $STATS_DIR/stats.pl 95 value '(\S+)\s+(Mbits/sec)' | awk '{if ($1 == "Mbits/sec") {printf("avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}}' | tee $dir_level_2/$RESULTS_DIR/$file_name
              # symlink newest results to plot_data dir
              #ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE
            else
              echo "unknown" $file_name
              echo "ERROR: unknown measurement type!"
              exit 1
            fi

          done
        fi
  done
done



#if [ $DO_PLOT -eq "1" ]
#then
#  read -p "Plot histograms: [ENTER]"
#  TMP_DIR=`pwd`
#  cd $BASE_DIR
#  gnuplot $STATS_DIR/plot-no_midfw
#  gnuplot $STATS_DIR/plot-with_pcfw
#  cd $TMP_DIR
#fi

