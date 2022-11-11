#!/usr/bin/env bash

#usage:
# $1 is vlan ID
# $2 is new ip
# $3 is default gateway

interface=$(ip addr show|egrep '^ *inet'|grep brd|awk -- '{ print $7; }'|sed -e 's:/[0-9]*$::')
echo $interface
oldIP=$(ip addr show|egrep '^ *inet'|grep brd|awk -- '{ print $2; }'|sed -e 's:/[0-9]*$::')
echo $oldIP
ip addr del $oldIP/8 dev $interface
sleep 2
ip link add link $interface name $interface.$1 type vlan id $1
sleep 2
ip addr add $2/24 dev $interface.$1
sleep 2
ip link set dev $interface.$1 up
sleep 2
ip route add default via $3
