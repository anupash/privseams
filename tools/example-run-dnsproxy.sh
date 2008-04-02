#! /bin/sh
# SERVER is the address of an existing resolver
# SERVERPORT is the port in SERVER, typically 53
# IP is our address
# PORT is the port number we are serving, typically 53
exec env SERVER=10.0.0.1 PORT=53 IP=127.0.0.1 SERVERPORT=53 ./dnsproxy.py -H hip-hosts
