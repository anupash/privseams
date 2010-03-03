#!/bin/sh
# useful for debugging: -xv

# This script eases up running the following performance measurements:
# - RTT
# - TCP throughput
# - UDP throughput

####### DON'T CHANGE BELOW HERE #######
ADDR_FAMILY=0
BANDWIDTH=100M
RUN_MODE=0
REMOTE_ADDRESS=0
PACKET_LENGTH=1370
MEASURE_TPUT=0
MEASURE_RTT=0
MEASUREMENT_COUNT=10
TCP_LENGTH=
FILE=0
RTT_POSTFIX=
TCP_POSTFIX=
UDP_POSTFIX=

# get the command line options
if [ $# -eq 0 ]
then
  echo "Usage: `basename $0` options: -a <family> [-n <value>] [-p <prefix>] -s|-c <dst> -r|-t <type> [-b <value>] [-l <length>]"
  echo
  echo "  -a <family>  = address family (4 - IPv4, 6 - IPv6)"
  echo "  -b <value>   = bandwith to be used for UDP measurements (append K or M)"
  echo "  -c <dst>     = client mode with destination ip address"
  echo "  -l <value>   = maximum packet length"
  echo "  -n <value>   = number of sequential measurements"
  echo "  -p <prefix>  = output file prefix (including absolut path)"
  echo "  -r           = measure RTT"
  echo "  -s           = server mode"
  echo "  -t <value>   = measure throughput (1 - TCP, 2 - UDP)"
  echo
  exit 0
fi

set -- `getopt a:b:c:l:n:rst: "$@"`
[ $# -lt 1 ] && exit 1    # getopt failed

while [ $# -gt 0 ]
do
  case "$1" in
    -a) ADDR_FAMILY=$2; shift;;
    -b) BANDWIDTH=$2; shift;;
    -c) RUN_MODE=1
        REMOTE_ADDRESS=$2; shift;;
    -l) PACKET_LENGTH=$2; shift;;
    -n) MEASUREMENT_COUNT=$2; shift;;
    -r) MEASURE_RTT=1;;
    -s) RUN_MODE=2;;
    -t) MEASURE_TPUT=$2; shift;;
    --) shift; break;;
    *) echo "Unknown option specified."
       exit 1;;
  esac
  shift
done

if [ $PACKET_LENGTH -ne "1370" ]
then
  TCP_LENGTH="-M "$PACKET_LENGTH
fi

if [ $FILE -ne "0" ]
then
  OUTPUT="tee --append $FILE"
  RTT_POSTFIX="-rtt"
  TCP_POSTFIX="-tcp"
  UDP_POSTFIX="-udp"
else
  OUTPUT="cat"
fi

# measure RTTs only on the client
if [ $MEASURE_RTT -eq "1" ]
then
  read -p "Measure RTT: [ENTER]" TMP

  if [ ! $REMOTE_ADDRESS = "0" ]
  then
    if [ $ADDR_FAMILY -eq "4" ]
    then
      ping -c $MEASUREMENT_COUNT $REMOTE_ADDRESS #| $OUTPUT$RTT_POSTFIX
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      ping6 -c $MEASUREMENT_COUNT $REMOTE_ADDRESS #| $OUTPUT$RTT_POSTFIX
    else
      echo "ERROR: Address family not specified."
      exit 1
    fi
  else
    echo "ERROR: Neither IPv4 nor IPv6 address specified."
    exit 1
  fi
fi


# measure TCP throughput
if [ $MEASURE_TPUT -eq "1" ]
then
  read -p "Measure TCP throughput (start server first!): [ENTER]" TMP

  # client side
  if [ $RUN_MODE -eq "1" -a ! $REMOTE_ADDRESS = "0" ]
  then

    i=0

    if [ $ADDR_FAMILY -eq "4" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -c $REMOTE_ADDRESS $TCP_LENGTH | $OUTPUT$TCP_POSTFIX
        i=`expr $i + 1`
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V -c $REMOTE_ADDRESS $TCP_LENGTH | $OUTPUT$TCP_POSTFIX
        i=`expr $i + 1`
        sleep 2
      done
    else
      echo "ERROR: Address family not specified."
      exit 1
    fi

  # server side
  elif [ $RUN_MODE -eq "2" ]
  then
    if [ $ADDR_FAMILY -eq "4" ]
    then
      iperf -s $TCP_LENGTH
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      iperf -V -s $TCP_LENGTH
    else
      echo "ERROR: Address family not specified."
      exit 1
    fi
  else
    echo "ERROR: Trying to run throughput measurements without specifying client (with destination address) or server mode."
  fi
fi


#measure UDP throughput
if [ $MEASURE_TPUT -eq "2" ]
then
  read -p "Measure UDP throughput (start server first!): [ENTER]" TMP

  # client side
  if [ $RUN_MODE -eq "1" -a ! $REMOTE_ADDRESS = "0" ]
  then

    i=0

    if [ $ADDR_FAMILY -eq "4" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -c $REMOTE_ADDRESS --udp --len $PACKET_LENGTH --bandwidth $BANDWIDTH | $OUTPUT$UDP_POSTFIX
        i=`expr $i + 1`
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V -c $REMOTE_ADDRESS --udp --len $PACKET_LENGTH --bandwidth $BANDWIDTH | $OUTPUT$UDP_POSTFIX
        i=`expr $i + 1`
        sleep 2
      done
    else
      echo "ERROR: Address family not specified."
      exit 1
    fi

  # server side
  elif [ $RUN_MODE -eq "2" ]
  then
    if [ $ADDR_FAMILY -eq "4" ]
    then
      iperf -s --udp --len $PACKET_LENGTH
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      iperf -V -s --udp --len $PACKET_LENGTH
    else
      echo "ERROR: Address family not specified."
      exit 1
    fi
  else
    echo "ERROR: Trying to run throughput measurements without specifying client (with destination address) or server mode."
  fi
fi
