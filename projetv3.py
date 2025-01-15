# -*- coding: utf-8 -*-
"""
Created on Fri Dec 27 17:10:17 2024

@author: anonyme
"""

import feedparser, requests, re, pandas as pd, smtplib
from datetime import datetime
from time import sleep
from email.mime.text import MIMEText

def chronometre(start, end):
    return f"Durée : {end - start}"

def type_publication(link):
    nom = link[29:link.index('/feed')] if '/feed' in link else link[29:-1]
    if nom == "alerte" :
        return "Alerte"
    elif nom == "cti" :
        return "Menace"
    elif nom == "avis" :
        return "Avis"
    elif nom == "ioc" :
        return "Indicateurs de compromission"
    elif nom == "dur" :
        return "Durcissement et recommandations"
    elif nom == "actualite" :
        return "Bulletin d'actualité"
    else:
        return "Inconnu"
   
def recuperer_donnees(link): 
    try :
        sleep(2)
        response = requests.get(link)
        return response.json()
    except Exception as e:
        print(f"Erreur d'accès à {link} :\n{e}")
        return None

def recuperer_feed(url):
    print("\n\nEtape 1 - Récupération des flux RSS en cours...")
    feed = []
    for link in url :
        feed.extend(feedparser.parse(link).entries)
        sleep(2)
    print(f"\nEtape 1 effectuée. {len(feed)} entrées récupérées.")
    return feed
 
def extraction_cves(rss_feed):
    print('\n\nEtape 2 : Extraction des CVE en cours...')
    all_CVE = []
    for entry in rss_feed :
        try :
            data = recuperer_donnees(entry.link +'json/')            
            # ref_cves = list(data["cves"])
            
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cve_list = list(set(re.findall(cve_pattern, str(data))))
            
            all_CVE.append(cve_list)
        except Exception as e :
            print(f"Erreur d'accès au lien JSON de l'entrée : {e}")
    print(f"\nEtape 2 effectuée. {sum([len(x) for x in all_CVE])} CVE extraites.")
    return all_CVE

def recherche_donnee_cve(data):
    if not data:  # Vérifie si data est None ou vide
        print("Aucune donnée trouvée pour ce CVE.")
        return {
            'description': "Non disponible",
            'severity': "None",
            'cvss_score': "Non disponible",
            'cwe_id': "Non disponible",
            'cwe_desc': "Non disponible",
            'vendor': "Non disponible",
            'product_name': "Non disponible",
            'versions': "Non disponible"
        }

    cna_containers = data.get("containers", {}).get("cna", {})
    adp_containers = data.get("containers", {}).get("adp", [{}])[0]

    description = cna_containers.get("descriptions", [{}])[0].get("value") or adp_containers.get("descriptions", [{}])[0].get("value")
    severity, cvss_score = "None", 0
    
    metrics = cna_containers.get("metrics", []) or adp_containers.get("metrics", [])
    if metrics:
        for metric in metrics:
            for key, value in metric.items():
                if "cvss" in key:
                    severity = value.get("baseSeverity", "None")
                    cvss_score = value.get("baseScore", 0)
    
    problem_types = (cna_containers.get("problemTypes", [{}])[0].get("descriptions", [{}])[0] or
                     adp_containers.get("problemTypes", [{}])[0].get("descriptions", [{}])[0])
    
    cwe_id = problem_types.get("cweId", "Non disponible")
    cwe_desc = problem_types.get("description", "Non disponible")

    vendor, product_name, versions = "Non disponible", "Non disponible", "Non disponible"
    affected = cna_containers.get("affected", []) or adp_containers.get("affected", [])
    for product in affected:
        vendor = product.get("vendor", "Non disponible")
        product_name = product.get("product", "Non disponible")
        versions = [v.get("version") for v in product.get("versions", []) if v.get("status") == "affected"]

    return {
        'description': description,
        'severity': severity,
        'cvss_score': cvss_score,
        'cwe_id': cwe_id,
        'cwe_desc': cwe_desc,
        'vendor': vendor,
        'product_name': product_name,
        'versions': ", ".join(versions)
    }


def enrichissement_cves(all_CVE, rss_feed):
    print("\n\nEtapes 3 et 4 : Enrichissement des CVE et consolidation des données en cours...")
    data_rows = []
    columns = ['Titre ANSSI', 'Référence ANSSI', 'Type', 'Date', 'CVE', 'CVSS', 'Base Severity', 'CWE', 'Description CWE', 'EPSS', 'Lien', 'Description', 'Editeur', 'Produit', 'Versions affectées']
    
    for entry, CVEs in zip(rss_feed, all_CVE) :
        for cve_id in CVEs :
            cve_data = recuperer_donnees(f"https://cveawg.mitre.org/api/cve/{cve_id}").get('containers', None)
            if not cve_data :
                print(f"Impossible de récupérer les données pour le CVE : {cve_id}")
                continue
            data = recherche_donnee_cve(cve_data)

            # Extraire le score EPSS
            epss_data = recuperer_donnees(f"https://api.first.org/data/v1/epss?cve={cve_id}").get("data", [])
            epss_score = epss_score = epss_data[0].get("epss") if epss_data else None

            #Création du df :
            title = entry['title']
            title = title[: title.index('(') - 1]
            
            publication_date = datetime.strptime(entry.published, "%a, %d %b %Y %H:%M:%S %z").strftime("%Y-%m-%d")
            
            data_rows.append([
                title, #titre ANSSI
                entry.link[entry.link.index('CERT'): -1], #Référence ANSSI
                type_publication(entry.link), #Type de publication
                publication_date, #Date
                cve_id, #CVE
                data.get('cvss_score'), #CVSS
                data.get('severity'), #Base Severity
                data.get('cwe_id'), #CWE
                data.get('cwe_desc'), #Description CWE
                epss_score, #EPSS
                entry.link, #Lien
                data.get('description'), #Description
                data.get('vendor'), #Editeur
                data.get('product_name'), #Produit
                data.get('versions') #Versions affectées
                ])
    df = pd.DataFrame(data, columns= columns)
    df.to_csv("donnees_cybersec.csv", index=False, encoding="utf-8")
    print("\nConsolidation des données effectuée et exportée dans 'donnees_cybersec.csv'.")


#Modifier pour que l'envoi de mail fonctionne
def send_email(to_email, subject, body):
    from_email = "anonymousatESILV@gmail.com"
    password = "QYp0lrvb2QTC5y"
    
    msg = MIMEText(body)
    msg['From'] = f"CERT-FR <{from_email}>"
    msg['To'] = to_email
    msg['Subject'] = subject

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            try:
                server.login(from_email, password)
                server.sendmail(from_email, to_email, msg.as_string())
                print(f"Alerte envoyée à {to_email}.")
            except Exception as e:
                print(f"Erreur lors de l'envoi de l'alerte : {e}")


# for i in range(len(df)) :
#     if df_export.loc[i,'Base Severity'] == 'Critical':
#         title = df_export.loc[i,'Titre ANSSI']
#         send_email("camille.espieux@gmail.com", "Alerte CVE critique", "Mettez à jour votre serveur " + title[title.index('dans') + 5 :] + " immédiatement.")


#def ANSSI():
print("Démarrage du programme ANSSI")
start = datetime.now()

#url = ["https://www.cert.ssi.gouv.fr/alerte/feed", "https://www.cert.ssi.gouv.fr/cti/feed","https://www.cert.ssi.gouv.fr/avis/feed", "https://www.cert.ssi.gouv.fr/ioc/feed", "https://www.cert.ssi.gouv.fr/dur/feed", "https://www.cert.ssi.gouv.fr/actualite/feed"]
url = ["https://www.cert.ssi.gouv.fr/alerte/feed","https://www.cert.ssi.gouv.fr/avis/feed"]

rss_feed = recuperer_feed(url)
all_CVE = extraction_cves(rss_feed)
print(all_CVE)

#%%
enrichissement_cves(all_CVE, rss_feed)

end = datetime.now()
print(f"Fin du programme.\n{chronometre(start, end)}")
    
#ANSSI()