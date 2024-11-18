#!/bin/bash
ip addr add 192.168.1.2/24 dev eth0
ip link set eth0 up
ip route add default via 192.168.1.1
echo "nameserver 8.8.8.8" > /etc/resolv.conf