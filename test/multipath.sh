#!/bin/sh

action=$1
iface=""
iftype=""
config=""

do_usage() 
{
    echo "multipath usage"
    echo "    multipath ifup[type<wifi[ifcae[config-file]]|eth>]|ifdown [iface]|bex" 
}

startwifi() 
{
    echo "bringing up WI-FI interface $1"
 #   ifdown $1
 #   ifup $1
    rm -rf /var/run/wpa_supplicant/wlan0 
    wpa_supplicant -i $1 -Dwext -c $2 -B >2 /dev/null
    dhclient $1
    
}

ifdown() 
{
    echo "Bringing down the interface $1"
    ifconfig $1 down
}


initbex() 
{
    echo "Starting base exchange"
}

if [ $action="ifup" ]
then
    iftype=$2
    if [ $iftype = "wifi" ]
    then
	iface=$3
	config=$4
	startwifi $iface $config
	
    fi
elif [ $action="bex" ]  
then
    initbex
elif [ $action="ifdown" ]
then
    ifdown $1
else 
    do_usage
fi