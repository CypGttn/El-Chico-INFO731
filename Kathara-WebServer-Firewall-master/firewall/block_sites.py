import csv
import socket
import subprocess
from urllib.parse import urlparse

# Liste des IP des utilisateurs autorisés à accéder aux sites bloqués
allowed_ips = {"5.5.7.2", "5.5.8.2"}

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

# Fonction pour ajouter une exception pour les IP autorisées
def add_allow_rule(ip):
    try:
        # Ajouter une règle pour autoriser les utilisateurs à accéder à l'IP
        for allowed_ip in allowed_ips:
            subprocess.run(
                ["iptables-legacy", "-A", "FORWARD", "-s", allowed_ip, "-d", ip, "-j", "ACCEPT"],
                check=True
            )
            print(f"Exception ajoutée : {allowed_ip} peut accéder à {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'ajout de l'exception pour {ip}: {e}")
    except Exception as e:
        print(f"Erreur inattendue lors de l'ajout de l'exception pour {ip}: {e}")

# Fonction pour bloquer l'IP avec iptables
def block_ip(ip):
    try:
        # Bloquer l'IP avec iptables (si aucune exception n'est en place)
        subprocess.run(["iptables-legacy", "-A", "FORWARD", "-d", ip, "-j", "REJECT"], check=True)
        print(f"Site avec IP {ip} bloqué.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du blocage de l'IP {ip}: {e}")
    except Exception as e:
        print(f"Erreur inattendue lors du blocage de l'IP {ip}: {e}")

# Lire le fichier CSV contenant des sites à bloquer et appliquer les règles
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
            # Ajouter des exceptions pour les IP autorisées
            add_allow_rule(ip)
            # Bloquer l'IP
            block_ip(ip)
        else:
            print(f"Impossible de résoudre l'IP pour {url}")




# Lire le fichier CSV contenant tous les sites et le fichier CSV contenant des mots à bannir
with open('all_sites.csv', newline='') as all_sites, open('swear_words.csv', newline='') as swear_words:
    reader1 = csv.reader(all_sites)
    reader2 = csv.reader(swear_words)
    next(reader1)  # Ignore la première ligne d'en-têtes du fichier all_sites.csv
    next(reader2)  # Ignore la première ligne d'en-têtes du fichier swear_words.csv
    
    # Convertir les mots à bannir en liste (cela évite de réouvrir reader2 dans chaque itération)
    swear_words_list = [row[0].strip() for row in reader2]
    
    # Traitement des deux fichiers CSV
    for row1 in reader1:
        url = row1[0].strip()  # Enlever les espaces autour de l'URL
        if not url:
            continue  # Ignore les lignes vides

        # Vérification des mots à bannir
        for swear_word in swear_words_list:
            if swear_word in url:
                print(f"Mot interdit '{swear_word}' trouvé dans l'URL: {url}")
                
                # Résoudre l'IP de l'URL
                ip = get_ip_from_url(url)
                if ip:
                    # Ajouter des exceptions pour les IP autorisées (si nécessaire)
                    add_allow_rule(ip)
                    
                    # Bloquer l'IP
                    block_ip(ip)
                else:
                    print(f"Impossible de résoudre l'IP pour {url}")
                break  # Quitte la boucle de vérification des mots à bannir dès qu'on en trouve un
