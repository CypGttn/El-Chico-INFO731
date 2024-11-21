import time
import csv
import socket
from scapy.all import sniff

nom_utilisateur=socket.gethostname()

# on enregistre les connexions dans un fichier csv
csv_file=f"/shared/{nom_utilisateur}_connections.csv"

# Créer un fichier CSV si il n'existe pas déjà, avec des en-têtes
with open(csv_file, mode='w', newline='') as file:
    writer=csv.writer(file)
    writer.writerow(['Date', 'Nom_Utilisateur', 'IP_Source', 'IP_Destination', 'Protocole', 'Status'])

# Fonction de traitement des paquets
def packet_callback(pkt):
    # Vérifier si le paquet a des informations IP
    if pkt.haslayer('IP'):
        date=time.strftime('%Y-%m-%d %H:%M:%S')
        ip_src=pkt['IP'].src
        ip_dst=pkt['IP'].dst

        # Vérifier si le paquet a des informations TCP ou UDP
        if pkt.haslayer('TCP'):
            proto='TCP'
        elif pkt.haslayer('UDP'):
            proto='UDP'
        else:
            proto='NA'

        # Écrire les informations du paquet dans le fichier CSV
        with open(csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([date, 'Nom_Utilisateur', ip_src, ip_dst, proto])

# Fonction pour démarrer la capture des paquets
def start_packet_capture():
    print("Démarrage de la capture des paquets...")
    sniff(prn=packet_callback, store=0, filter="ip", count=0)

# Lancer la capture des paquets (en arrière-plan)
start_packet_capture()
