import csv
import socket
import subprocess
from urllib.parse import urlparse

# Fonction pour obtenir l'IP d'une URL
def get_ip_from_url(url):
    try:
        # Extraire le nom de domaine de l'URL (en retirant le http:// ou https://)
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        print(f"Nom de domaine extrait : {domain}")

        # Résoudre l'IP du domaine
        ip = socket.gethostbyname(domain)
        print(f"IP résolue pour {domain}: {ip}")
        return ip
    except socket.gaierror as e:
        print(f"Erreur de résolution pour {url}: {e}")
        return None
    except Exception as e:
        print(f"Erreur inattendue lors de la résolution pour {url}: {e}")
        return None

# Fonction pour bloquer l'IP avec iptables
def block_ip(ip):
    try:
        # Bloquer l'IP avec iptables
        subprocess.run(["iptables-legacy", "-A", "OUTPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables-legacy", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"Site avec IP {ip} bloqué.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du blocage de l'IP {ip}: {e}")
    except Exception as e:
        print(f"Erreur inattendue lors du blocage de l'IP {ip}: {e}")

# Lire le fichier CSV et bloquer les sites
with open('blocked_sites.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # Ignore la première ligne d'en-têtes
    for row in reader:
        url = row[0].strip()  # Enlever les espaces autour de l'URL
        if not url:
            continue  # Ignore les lignes vides

        print(f"Traitement de l'URL: {url}")
        
        # Résoudre l'IP de l'URL
        ip = get_ip_from_url(url)
        
        if ip:
            # Bloquer l'IP
            block_ip(ip)
        else:
            print(f"Impossible de résoudre l'IP pour {url}")
