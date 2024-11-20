#!/bin/bash

# Variables
BLOCKED_SITES_FILE="blocked_sites.csv"
EXCLUDED_IPS=("5.5.7.2" "5.5.8.2")  # IPs des machines 'bank' et 'minister'

# Activer le forwarding IP
echo 1 > /proc/sys/net/ipv4/ip_forward

# Réinitialiser les règles iptables
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Bloquer les sites pour toutes les machines sauf exceptions
if [[ -f $BLOCKED_SITES_FILE ]]; then
  while IFS= read -r DOMAIN; do
    # Résoudre le domaine en IP(s)
    for IP in $(dig +short $DOMAIN | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); do
      # Ajouter une règle DROP pour bloquer l'accès à ce domaine
      iptables -A FORWARD -d $IP -j DROP
    done
  done < "$BLOCKED_SITES_FILE"
fi

# Ajouter des règles pour exclure les machines 'bank' et 'minister'
for EXCLUDED_IP in "${EXCLUDED_IPS[@]}"; do
  iptables -A FORWARD -s $EXCLUDED_IP -j ACCEPT
done

# Permettre tout autre trafic légitime
iptables -A FORWARD -j ACCEPT
