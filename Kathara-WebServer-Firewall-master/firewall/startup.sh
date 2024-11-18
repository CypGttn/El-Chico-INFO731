#!/bin/bash
ip addr add 192.168.1.1/24 dev eth0
ip addr add 192.168.2.1/24 dev eth1
ip addr add 192.168.3.1/24 dev eth2
ip addr add 192.168.4.1/24 dev eth3

ip link set eth0 up
ip link set eth1 up
ip link set eth2 up
ip link set eth3 up

# Activer le forwarding IP
echo 1 > /proc/sys/net/ipv4/ip_forward

# Ajouter les règles NAT
iptables -t nat -A POSTROUTING -o eth5 -j MASQUERADE

# Permettre le trafic de retour
iptables -A FORWARD -i eth5 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o eth5 -j ACCEPT