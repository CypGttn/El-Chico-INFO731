# -*- coding: utf-8 -*- 

import time
import csv
import socket
from scapy.all import sniff

nom_utilisateur=socket.gethostname()

# on enregistre les connexions dans un fichier csv
csv_file="shared/{}_connections.csv".format(nom_utilisateur)

# on créé le fichier avec les en tete voulu
with open(csv_file, mode='w', newline='') as file:
    writer=csv.writer(file)
    writer.writerow(['Date', 'NomUtilisateur', 'IPSource', 'IPDestination', 'Protocole', 'Status'])

def packet_callback(pkt):
        date=time.strftime('%Y-%m-%d %H%M%S')
        ip_src=pkt['IP'].src
        ip_dst=pkt['IP'].dst
        # on regarde si le protocole est TCP ou UDP
        if pkt.haslayer('TCP'):
            proto='TCP'
        elif pkt.haslayer('UDP'):
            proto='UDP'
        else:
            proto='NA'

        # on enregistre les informations
        with open(csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([date, nom_utilisateur, ip_src, ip_dst, proto])

# on lance la capture des paquets
def start_packet_capture():
    print("Démarrage de la capture des paquets...")
    sniff(prn=packet_callback, store=0, filter="ip", count=0)

# Lancer la capture des paquets (en arrière-plan)
start_packet_capture()