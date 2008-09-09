#!/bin/bash
# useful for debugging: -xv

DST_IPv4=192.168.1.103
DST_IPv6=
DST_HIT=
ROUTE_TOv4=192.168.1.101
ROUTE_TOv6=

MEASUREMENT_COUNT=20

HIPL_DIR=~/dev/hipl--esp--2.6/
HIPD_DIR=$HIPL_DIR/hipd
HIPFW_DIR=$HIPL_DIR/firewall
HIPFW_OPTS=
STATS_DIR=$HIPL_DIR/test/performance

BASE_DIR=~/dev/measurements/$(date +%Y_%m_%d)
FILE_PREFIX=
FILE_POSTFIX=
OUTPUT_DIR=$BASE_DIR/output
STAGING_DIR=$BASE_DIR/staging
RESULTS_DIR=$BASE_DIR/results

# needed by the script - don't change these variables
DEVICE_TYPE=0
ADDR_FAMILY=0
RUN_HIPD=0
RUN_HIPFW=0
RUN_USERIPSEC=0
RUN_ESPEXT=0
WITH_REORDER=0
WITH_MID=0
MEASURE_RTT=0
MEASURE_TPUT=0
VERIFY_PATH=0

FILE=

# get the command line options
NO_ARGS=0

if [ $# -eq "$NO_ARGS" ]
then
  echo "Usage: `basename $0` options: -a <family> -t <type> [-defimMorv] [-p <type>]"
  echo
  echo "  -a <family>  = address family (4 - IPv4, 6 - IPv6)"
  echo "  -t <type>    = device type (1 - client, 2 - middlebox, 3 - server)"
  echo "  -d           = start hipd (only client/server)"
  echo "  -f           = start hipfw (with conntrack, if ! -i or -e)"
  echo "  -i           = start hipfw with userspace ipsec (no conntrack)"
  echo "  -e           = start hipfw with ESP extension (no conntrack)"
  echo "  -r           = measure RTT"
  echo "  -p <type>    = measure throughput (1 - tcp, 2 - udp, 3 - both)"
  echo "  -o           = tests are run with packet reordering using WANem"
  echo "  -m           = tests are run with hipfw on middlebox-PC"
  echo "  -M           = tests are run with hipfw on a router"
  echo "  -v           = verify path"
  echo
  exit 0
fi

while getopts ":a:defit:mMop:rv" CMD_OPT
do
  case $CMD_OPT in
    a) ADDR_FAMILY=$OPTARG;;
    d) RUN_HIPD=1;;
    e) RUN_HIPFW=1
       RUN_ESPEXT=1;;
    f) RUN_HIPFW=1;;
    i) RUN_HIPFW=1
       RUN_USERIPSEC=1;;
    t) DEVICE_TYPE=$OPTARG;;
    m) WITH_MID=1;;
    M) WITH_MID=2;;
    o) WITH_REORDER=1;;
    p) MEASURE_TPUT=$OPTARG;;
    r) MEASURE_RTT=1;;
    v) VERIFY_PATH=1;;
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
  FILE_PREFIX=$FILE_PREFIX"with_pcfw-"
elif [ $WITH_MID -eq "2" ]
then
  FILE_PREFIX=$FILE_PREFIX"with_routerfw-"
else
  FILE_PREFIX=$FILE_PREFIX"no_midfw-"
fi

if [ $WITH_REORDER -eq "1" ]
then
  FILE_PREFIX=$FILE_PREFIX"with_reorder-"
else
  FILE_PREFIX=$FILE_PREFIX"no_reorder-"
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
# TODO check the necessary files and dirs


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

# set up routes on all devices
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
  FILE=$FILE_PREFIX"rtt-"$FILE_POSTFIX
  read -p "Measure RTT: [ENTER]"

  if [ $RUN_HIPD -eq "1" ]
  then
    ping6 -c $MEASUREMENT_COUNT $DST_HIT | tee --append $OUTPUT_DIR/$FILE
  elif [ $ADDR_FAMILY -eq "4" ]
  then
    ping -c $MEASUREMENT_COUNT $DST_IPv4 | tee --append $OUTPUT_DIR/$FILE
  elif [ $ADDR_FAMILY -eq "6" ]
  then
    ping6 -c $MEASUREMENT_COUNT $DST_IPv6 | tee --append $OUTPUT_DIR/$FILE
  else
    echo "ERROR: Neither HIT nor correct address family specified."
    exit 1
  fi

  # output post-processing
  grep rtt $OUTPUT_DIR/$FILE | tee --append $STAGING_DIR/$FILE
fi


# measure TCP throughput
if [ $MEASURE_TPUT -eq "1" -o $MEASURE_TPUT -eq "3" ]
then

  read -p "Measure TCP throughput (start server first!): [ENTER]"

  # client side
  if [ $DEVICE_TYPE -eq "1" ]
  then
    FILE=$FILE_PREFIX"tcp-"$FILE_POSTFIX
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
    grep MBytes $OUTPUT_DIR/$FILE | $STATS_DIR/stats.pl 95 type '(MBytes)\s+(\S+)' | tee --append $STAGING_DIR/$FILE

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
    OUTPUT_FILE=$OUTPUT_FILE_PREFIX"udp-"$OUTPUT_FILE_POSTFIX
    i=0
    if [ $RUN_HIPD -eq "1" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_HIT --udp --len 1370 --bandwidth 100M | tee --append $OUTPUT_DIR/$OUTPUT_FILE
        i=`expr $i + 1`
        sleep 2
      done 
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf --client $DST_IPv4 --udp --len 1370 --bandwidth 100M | tee --append $OUTPUT_DIR/$OUTPUT_FILE
        i=`expr $i + 1`
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_IPv6 --udp --len 1370 --bandwidth 100M | tee --append $OUTPUT_DIR/$OUTPUT_FILE
        i=`expr $i + 1`
        sleep 2
      done
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi

    # client-side output post-processing
    #grep MBytes $OUTPUT_DIR/$FILE | $STATS_DIR/stats.pl 95 type '(MBytes)\s+(\S+)' | tee --append $STAGING_DIR/$FILE

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

exit 0

