#!/bin/sh

IP1=192.168.1.14
IP2=192.168.1.4
IF1=eth0
IF2=wlan0
MASK=24
SUBNET=192.168.1.0
GATEWAY=192.168.1.1

bring_eth_up()
{

    ip route flush cache;

    ip address add $IP1/$MASK dev $IF1;

    ip rule add from $IP1 prio 1 table 1;
    
    ip route add $SUBNET/$MASK proto kernel dev $IF1 src $IP1 table 1;
    
}

bring_eth_down() 
{
    echo "<<< Removind IP address $IP1 from interface $IF1 >>>"
    ip address del $IP1/$MASK dev $IF1;
    ip rule del from $IP1 prio 1;
}

bring_wlan_up()
{

    ip route flush cache;

    ip address add $IP2/$MASK dev $IF2;

    ip rule add from $IP2 prio 2 table 2;
    
    ip route add $SUBNET/$MASK proto kernel dev $IF2 src $IP2 table 2;
    
}

bring_wlan_down() 
{
    echo "<<< Removind IP address $IP2 from interface $IF2 >>>"
    ip address del $IP2/$MASK dev $IF2;
    ip rule del from $IP2 prio 2;
}

#ip route add $SUBNET/$MASK proto kernel dev $IF2 table main
#ip route add default via $GATEWAY dev $IF2 table main

#echo "ip route add 192.168.1.0/24 proto kernel dev $IF2 src $IP2 table 2"
#ip route add 192.168.1.0/24 proto kernel dev $IF2 src $IP2 table 2
#echo "ip route add 192.168.1.0/24 proto kernel dev $IF1 src $IP1 table 1"


#echo "ip route add default via $GATEWAY dev $IF2 table 2"
#ip route add default via $GATEWAY dev $IF2 table 2
#echo "ip route add default via $GATEWAY dev $IF1 table 1"
#ip route add default via $GATEWAY dev $IF1 table 1

if [ $2 = "up" ]
then
    if [ $1 = "eth0" ] 
    then
	bring_eth_up
    elif [ $1 = "wlan0" ]
    then
	bring_wlan_up
    fi
elif [ $2 = "down" ]
then
    if [ $1 = "eth0" ] 
    then
	bring_eth_down
    elif [ $1 = "wlan0" ]
    then
	bring_wlan_down
    fi
fi
