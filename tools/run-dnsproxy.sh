#! /bin/sh
# SERVER is the address of an existing resolver
# SERVERPORT is the port in SERVER, typically 53
# IP is our address
# PORT is the port number we are serving, typically 53

SERVER=`grep ^nameserver /etc/resolv.conf|head -1|cut -d' ' -f2`
PORT=53
IP=127.0.0.1
SERVERPORT=53
HIP_HOSTS=/etc/hip/hosts

if test $PORT -lt 1024 && test `id -u` -ne 0
then
	echo "Port $PORT requires root privileges"
	exit
fi

exec env SERVER=$SERVER PORT=$PORT IP=$IP SERVERPORT=$SERVERPORT ./dnsproxy.py -H $HIP_HOSTS
