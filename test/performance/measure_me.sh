#!/bin/bash
# useful for debugging: -xv

DST_IPv4=192.168.1.102
DST_IPv6=0
DST_HIT=2001:13:829c:5639:1606:cd1:65c5:64e
ROUTE_TOv4=0
ROUTE_TOv6=0

MEASUREMENT_COUNT=20

HIPL_DIR=~/dev/hipl--esp--2.6
HIPD_DIR=$HIPL_DIR/hipd
HIPFW_DIR=$HIPL_DIR/firewall
HIPFW_OPTS=
STATS_DIR=$HIPL_DIR/test/performance

BASE_DIR=~/dev/measurements
EXT_BASE_DIR=$BASE_DIR/$(date +%Y_%m_%d)
FILE_PREFIX=
FILE_POSTFIX=
OUTPUT_DIR=$EXT_BASE_DIR/output
STAGING_DIR=$EXT_BASE_DIR/staging
RESULTS_DIR=$EXT_BASE_DIR/results
PLOT_DATA_DIR=$BASE_DIR/current_data

# needed by the script - don't change these variables
DEVICE_TYPE=0
ADDR_FAMILY=0
RUN_HIPD=0
RUN_HIPFW=0
RUN_USERIPSEC=0
RUN_ESPEXT=0
WITH_REORDER=0
WITH_MID=0
WITH_HIPFW=0
WITH_WANEM=0
MEASURE_RTT=0
MEASURE_TPUT=0
BANDWIDTH=100M
VERIFY_PATH=0
DO_PLOT=0

FILE=

# get the command line options
NO_ARGS=0

if [ $# -eq "$NO_ARGS" ]
then
  echo "Usage: `basename $0` options: -a <family> -t <type> [-defilorvw] [-m|M <value>] [-p <type> [-b <value>]]"
  echo
  echo "  -a <family>  = address family (4 - IPv4, 6 - IPv6)"
  echo "  -t <type>    = device type (1 - client, 2 - middlebox, 3 - server)"
  echo "  -d           = start hipd (only client/server)"
  echo "  -f           = start hipfw (with conntrack, if ! -i or -e)"
  echo "  -i           = start hipfw with userspace ipsec (no conntrack)"
  echo "  -e           = start hipfw with ESP extension (no conntrack)"
  echo "  -r           = measure RTT"
  echo "  -p <type>    = measure throughput (1 - tcp, 2 - udp)"
  echo "  -b <value>   = bandwith to be used for udp measurements (include K or M)"
  echo "  -w           = tests are run with WANem on the route"
  echo "  -o           = tests are run with packet reordering using WANem"
  echo "  -m <value>   = tests are run with middlebox-PC (0 - hipfw off, 1 - hipfw on)"
  echo "  -M <value>   = tests are run with a router (0 - hipfw off, 1 - hipfw on)"
  echo "  -v           = verify path"
  echo "  -l           = plot histograms"
  echo
  exit 0
fi

while getopts ":a:b:defit:lm:M:op:rvw" CMD_OPT
do
  case $CMD_OPT in
    a) ADDR_FAMILY=$OPTARG;;
    b) BANDWIDTH=$OPTARG;;
    d) RUN_HIPD=1;;
    e) RUN_HIPD=1
       RUN_HIPFW=1
       RUN_USERIPSEC=1
       RUN_ESPEXT=1;;
    f) RUN_HIPFW=1;;
    i) RUN_HIPD=1
       RUN_HIPFW=1
       RUN_USERIPSEC=1;;
    t) DEVICE_TYPE=$OPTARG;;
    l) DO_PLOT=1;;
    m) WITH_MID=1
       WITH_HIPFW=$OPTARG;;
    M) WITH_MID=2
       WITH_HIPFW=$OPTARG;;
    o) WITH_WANEM=1
       WITH_REORDER=1;;
    p) MEASURE_TPUT=$OPTARG;;
    r) MEASURE_RTT=1;;
    v) VERIFY_PATH=1;;
    w) WITH_WANEM=1;;
    *) echo "Unknown option specified."
       exit 1;;
  esac
done
shift $((OPTIND - 1))


# set the output file's prefix
if [ $RUN_HIPD -eq "1" ]
then
  FILE_PREFIX=$FILE_PREFIX"with_hipd-"
else
  FILE_PREFIX=$FILE_PREFIX"no_hipd-"
fi

if [ $RUN_USERIPSEC -eq "1" ]
then
  FILE_PREFIX=$FILE_PREFIX"with_useripsec-"
else
  FILE_PREFIX=$FILE_PREFIX"with_kernelipsec-"
fi

if [ $RUN_ESPEXT -eq "1" ]
then
  FILE_PREFIX=$FILE_PREFIX"with_esp_ext-"
else
  FILE_PREFIX=$FILE_PREFIX"no_esp_ext-"
fi

if [ $WITH_MID -eq "1" ]
then
  if [ $WITH_HIPFW -eq "1" ]
  then
    FILE_PREFIX=$FILE_PREFIX"actice_pcfw-"
  else
    FILE_PREFIX=$FILE_PREFIX"inactive_pcfw-"
  fi
elif [ $WITH_MID -eq "2" ]
then
  if [ $WITH_HIPFW -eq "1" ]
  then
    FILE_PREFIX=$FILE_PREFIX"active_routerfw-"
  else
    FILE_PREFIX=$FILE_PREFIX"inactive_routerfw-"
  fi
else
  FILE_PREFIX=$FILE_PREFIX"no_midfw-"
fi

if [ $WITH_WANEM -eq "1" ]
then
  FILE_PREFIX=$FILE_PREFIX"with_wanem-"
  if [ $WITH_REORDER -eq "1" ]
  then
    FILE_PREFIX=$FILE_PREFIX"with_reorder-"
  else
    FILE_PREFIX=$FILE_PREFIX"no_reorder-"
  fi
else
  FILE_PREFIX=$FILE_PREFIX"no_wanem-"
fi


# create the directories for client, if they don't exist yet
if [ $DEVICE_TYPE -eq "1" ]
then
  if [ ! -e $BASE_DIR ]
  then
    mkdir $BASE_DIR
  fi

  if [ ! -e $EXT_BASE_DIR ]
  then
    mkdir $EXT_BASE_DIR
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
fi

# set hipfw parameters
if [ $RUN_USERIPSEC -eq "1" ]
then
  if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
  then
    HIPFW_OPTS=Fi
  else
    echo "WARNING: Trying to set userspace IPsec a middlebox or unspecified device."
  fi
fi

if [ $RUN_ESPEXT -eq "1" ]
then
  if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
  then
    HIPFW_OPTS=Fe
  elif [ $DEVICE_TYPE -eq "2" ]
  then
    HIPFW_OPTS=
  else 
    echo "ERROR: Unknown device type."
    exit 1
  fi
fi


# TODO check mandatory options


# disable redirection announcement and accept on all devices
if [ -e /proc/sys/net/ipv4/conf/all/accept_redirects ]
then
  for f in /proc/sys/net/ipv4/conf/*/accept_redirects
  do
    echo "0" > $f
  done
else
  echo "ERROR: proc-file not found."
  exit 1
fi

if [ -e /proc/sys/net/ipv4/conf/all/secure_redirects ]
then
  for f in /proc/sys/net/ipv4/conf/*/secure_redirects
  do
    echo "0" > $f
  done
else
  echo "ERROR: proc-file not found."
  exit 1
fi

if [ -e /proc/sys/net/ipv4/conf/all/send_redirects ]
then
  for f in /proc/sys/net/ipv4/conf/*/send_redirects
  do
    echo "0" > $f
  done
else
  echo "ERROR: proc-file not found."
  exit 1
fi

# TODO do the same for IPv6
echo "0" > /proc/sys/net/ipv6/conf/all/accept_redirects


# configure forwarding on middleboxes only
if [ $DEVICE_TYPE -eq "2" ]
then
  # enable forwarding
  echo "1" >/proc/sys/net/ipv4/conf/all/forwarding
  echo "1" >/proc/sys/net/ipv6/conf/all/forwarding
fi

# set up routes on all devices where the next hop is specified
if [ "$ROUTE_TOv4" != "0" -o "$ROUTE_TOv6" != "0" ]
then
  if [ $ADDR_FAMILY -eq "4" ]
  then
    route add -host $DST_IPv4 netmask 0.0.0.0 gw $ROUTE_TOv4
  elif [ $ADDR_FAMILY -eq "6" ]
  then
    echo "TODO route6 add"
    exit 1
  else
    echo "ERROR: Unknown address family or none specified."
    exit 1
  fi
fi


# start HIPL apps
if [ $RUN_HIPD -eq "1" -o $RUN_HIPFW -eq "1" ]
then

  read -p "Start HIPL apps: [ENTER]"

  if [ $RUN_HIPD -eq "1" ]
  then
    if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
    then
      $HIPD_DIR/hipd -kb
      ps -A | grep hipd
    else
      echo "WARNING: hipd specified on middlebox - currently not supported."
    fi
  fi

  if [ $RUN_HIPFW -eq "1" ]
  then
    if [ $RUN_HIPD -eq "1" ]
    then
      echo "Waiting a bit for hipd to start up..."
      sleep 2
    fi
    $HIPFW_DIR/hipfw -kb$HIPFW_OPTS
    ps -A | grep hipfw
  fi
fi


# only check correctness of the routes on the end-hosts
if [ $VERIFY_PATH -eq "1" ]
then
  if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
  then 

    read -p "Verify path: [ENTER]"

    if [ $RUN_HIPD -eq "1" ]
    then
      traceroute6 $DST_HIT
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      traceroute $DST_IPv4
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      traceroute6 $DST_IPv6
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi
  else
    echo "WARNING: Trying to use path verification on a middlebox or unspecified device."
  fi
fi


# measure RTTs only on the client
if [ $MEASURE_RTT -eq "1" -a $DEVICE_TYPE -eq "1" ]
then
  FILE=$FILE_PREFIX"rtt"$FILE_POSTFIX
  read -p "Measure RTT: [ENTER]"

  if [ $RUN_HIPD -eq "1" ]
  then
    ping6 -c $MEASUREMENT_COUNT $DST_HIT | tee $OUTPUT_DIR/$FILE
  elif [ $ADDR_FAMILY -eq "4" ]
  then
    ping -c $MEASUREMENT_COUNT $DST_IPv4 | tee $OUTPUT_DIR/$FILE
  elif [ $ADDR_FAMILY -eq "6" ]
  then
    ping6 -c $MEASUREMENT_COUNT $DST_IPv6 | tee $OUTPUT_DIR/$FILE
  else
    echo "ERROR: Neither HIT nor correct address family specified."
    exit 1
  fi

  # output post-processing
  grep 'from' $OUTPUT_DIR/$FILE | tr '=' ' ' | $STATS_DIR/stats.pl 95 type '(time)\s+(\S+)' | tee $STAGING_DIR/$FILE
  grep 'time' $STAGING_DIR/$FILE | awk '{printf("#avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}' | tee $RESULTS_DIR/$FILE
  # symlink newest results to plot_data dir
  ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE
fi


# measure TCP throughput
if [ $MEASURE_TPUT -eq "1" -o $MEASURE_TPUT -eq "3" ]
then

  read -p "Measure TCP throughput (start server first!): [ENTER]"

  # client side
  if [ $DEVICE_TYPE -eq "1" ]
  then
    FILE=$FILE_PREFIX"tcp"$FILE_POSTFIX
    
    # remove old measurement
    if [ -e $OUTPUT_DIR/$FILE ]
    then
      rm $OUTPUT_DIR/$FILE
    fi
    
    i=0

    if [ $RUN_HIPD -eq "1" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_HIT | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        # for some reason iperf needs this to reset the timer
        # for throughput calc
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf --client $DST_IPv4 | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_IPv6 | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi

    # client-side output post-processing
    grep 'sec' $OUTPUT_DIR/$FILE | awk '{printf("Mbits/sec "); printf("%.3f\n", $7)}' | $STATS_DIR/stats.pl 95 type '(Mbits/sec)\s+(\S+)' | tee $STAGING_DIR/$FILE
    grep 'Mbits/sec' $STAGING_DIR/$FILE | awk '{printf("#avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}' | tee $RESULTS_DIR/$FILE
    # symlink newest results to plot_data dir
    ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

  # server side
  elif [ $DEVICE_TYPE -eq "3" ]
  then
    if [ $RUN_HIPD -eq "1" ]
    then
      iperf -V --server
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      iperf --server
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      iperf -V --server
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi
  else
    echo "WARNING: Trying to run throughput measurements on a middlebox or unspecified device."
  fi
fi


#measure UDP throughput
if [ $MEASURE_TPUT -eq "2" -o $MEASURE_TPUT -eq "3" ]
then

  read -p "Measure UDP throughput (start server first!): [ENTER]"

  # client side
  if [ $DEVICE_TYPE -eq "1" ]
  then
    FILE=$FILE_PREFIX"udp"$FILE_POSTFIX
    
    # remove old measurement
    if [ -e $OUTPUT_DIR/$FILE ]
    then
      rm $OUTPUT_DIR/$FILE
    fi

    i=0

    if [ $RUN_HIPD -eq "1" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_HIT --udp --len 1370 --bandwidth $BANDWIDTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done 
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf --client $DST_IPv4 --udp --len 1370 --bandwidth $BANDWIDTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_IPv6 --udp --len 1370 --bandwidth $BANDWIDTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi

    # client-side output post-processing
    grep '%' $OUTPUT_DIR/$FILE | awk '{printf("Mbits/sec "); printf("%.3f\n", $7)}' | $STATS_DIR/stats.pl 95 type '(Mbits/sec)\s+(\S+)' | tee $STAGING_DIR/$FILE
    grep 'Mbits/sec' $STAGING_DIR/$FILE | awk '{printf("#avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}' | tee $RESULTS_DIR/$FILE
    # symlink newest results to plot_data dir
    ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

  # server side
  elif [ $DEVICE_TYPE -eq "3" ]
  then
    if [ $RUN_HIPD -eq "1" ]
    then
      iperf -V --server --udp --len 1370
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      iperf --server --udp --len 1370
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      iperf -V --server --udp --len 1370
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi
  fi
fi


if [ $RUN_HIPD -eq "1" -o $RUN_HIPFW -eq "1" ]
then
  read -p "Clean up: [ENTER]"

  if [ $RUN_HIPD -eq "1" ]
  then
    killall hipd
  fi

  if [ $RUN_HIPFW -eq "1" ]
  then
    killall hipfw
  fi
fi


if [ $DO_PLOT -eq "1" ]
then
  read -p "Plot histograms: [ENTER]"
  TMP_DIR=`pwd`
  cd $BASE_DIR
  gnuplot $STATS_DIR/plot-no_midfw
  gnuplot $STATS_DIR/plot-with_pcfw
  cd $TMP_DIR
fi


exit 0

