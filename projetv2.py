# -*- coding: utf-8 -*-
"""
Created on Fri Dec 27 17:10:17 2024

@author: anonyme
"""
import feedparser, requests, re, pandas as pd, smtplib, time
from datetime import datetime
from time import sleep
from email.mime.text import MIMEText

print("Lancement du programme")
start = datetime.now()

def recuperer_donnees(link): 
    try :
        sleep(2)
        response = requests.get(link)
        return response.json()
    except Exception as e:
        print(f"Erreur d'accès à {link} :\n{e}")
        return None

def chronometre(start, end):
    return f"Durée : {end - start}"

def Recuperer_Feed(feed, url):
    print("\n\nEtape 1 - Récupération des flux RSS en cours...")
    for link in url :
        feed.extend(feedparser.parse(link).entries)
        sleep(2)
    print(f"\nEtape 1 effectuée. {len(feed)} entrées récupérées.")
        

def Type_Publication(link):
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
    

rss_feed = []
#url = ["https://www.cert.ssi.gouv.fr/alerte/feed", "https://www.cert.ssi.gouv.fr/cti/feed","https://www.cert.ssi.gouv.fr/avis/feed", "https://www.cert.ssi.gouv.fr/ioc/feed", "https://www.cert.ssi.gouv.fr/dur/feed", "https://www.cert.ssi.gouv.fr/actualite/feed"]
url = ["https://www.cert.ssi.gouv.fr/alerte/feed","https://www.cert.ssi.gouv.fr/avis/feed"]

Recuperer_Feed(rss_feed, url)

#%% Etape 2
def extraction_cves(rss_feed, all_CVE):
    print('\n\nEtape 2 : Extraction des CVE en cours...')
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

all_CVE = []
extraction_cves(rss_feed, all_CVE)
#%% Etapes 3 & 4 :
print("\n\nEtapes 3 et 4 : Enrichissement des CVE et consolidation des données en cours...")

#df = [[] for i in range(14)]
dataframe = []
columns = ['Titre ANSSI', 'Référence ANSSI', 'Type', 'Data', 'CVE', 'CVSS', 'Base Severity', 'CWE', 'Description CWE', 'EPSS', 'Lien', 'Description', 'Editeur', 'Produit', 'Versions affectées']

#remplacer par len(all_CVE)
for m in range(len(all_CVE)) :
    for cve_id in all_CVE[m] :
        cve_data = recuperer_donnees(f"https://cveawg.mitre.org/api/cve/{cve_id}").get('containers', None)
        
        description = "Non disponible"   
        vendor = "Non disponible"
        product_name = "Non disponible"
        versions = "Non disponible"
        cwe = "Non disponible" #Demander si on peut remplacer Non disp par None pour Jupyter ensuite
        cwe_desc = "Non disponible" #à quoi ça sert ?
        severity = "None"
        cvss_score = 0
        
        if not cve_data :
            print(f"Impossible de récupérer les données pour le CVE : {cve_id}")
            continue
        
        donnee_CNA = cve_data.get("cna")
        donnee_ADP = cve_data.get("adp")
        
        if donnee_CNA :
            
            #extraction description
            description = donnee_CNA.get("descriptions")

            if description :
                description = description[0].get("value", "Non disponible")
                #print(description)
            
            #extraction score cvss
            cvss_score = donnee_CNA.get("metrics")
            
            if cvss_score :
                k = cvss_score[0].keys()
                key = [x for x in k if 'cvss' in x]

                if key != [] :   
                    severity = cvss_score[0].get(key[0], "None").get("baseSeverity", "None")
                    cvss_score = cvss_score[0].get(key[0], 0).get("baseScore", 0)      
                else:
                    cvss_score = 0
                    severity = "None"
    
            #extraction type de problèmes
            problemtype = donnee_CNA.get("problemTypes", {})
            if problemtype and "descriptions" in problemtype[0] :
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
                
            #extraction produits affectés
            affected = donnee_CNA.get("affected", None)
            if affected != None:
                for product in affected:
                    vendor = product.get("vendor", "Non disponible")
                    product_name = product.get("product", "Non disponible")
                    if "versions" in product.keys():
                        versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                    else :
                        versions = "Non disponible"
                    #print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")


        if donnee_ADP :
        #si le score CVSS n'est pas dans "cna", il est dans certains cas dans "adp"
            if not cvss_score or cvss_score == 0:
                cvss_score = donnee_ADP[0].get("metrics", None)
                
                if cvss_score != None:
                    k = cvss_score[0].keys()
                    key = [x for x in k if 'cvss' in x]

                    if key != [] :   
                        severity = cvss_score[0].get(key[0], "None").get("baseSeverity", "None")
                        cvss_score = cvss_score[0].get(key[0], 0).get("baseScore", 0)      
                    else:
                        cvss_score = 0
                        severity = "None"
                        
            #extraction type de problèmes
            if cwe == "Non disponible":
                problemtype = donnee_ADP[0].get("problemTypes", {})
                if problemtype and "descriptions" in problemtype[0] :
                    cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                    cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
            
            #extraction editeur, versions affectées ...
            if not affected :
                affected = donnee_ADP[0].get("affected", None)
                if affected :
                    for product in affected:
                        vendor = product.get("vendor", "Non disponible")
                        product_name = product.get("product", "Non disponible")
                        if "versions" in product.keys():
                            versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                        else :
                            versions = "Non disponible"
                        #print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")

         
        # Extraire le score EPSS
        epss_data = recuperer_donnees(f"https://api.first.org/data/v1/epss?cve={cve_id}").get("data", [])
        epss_score = None
        if epss_data != []:
            epss_score = epss_data[0].get("epss", None)
        
        #Création du df :
        entry = rss_feed[m] #réutilisation de m qui est l'index de l'entrée du flux et de ses CVEs associés
        title = entry['title']
        title = title[: title.index('(') - 1]
        
        formatted_date = datetime.strptime(entry.published, "%a, %d %b %Y %H:%M:%S %z").strftime("%Y-%m-%d")
        
        dataframe.append([
            title, #titre ANSSI
            entry.link[entry.link.index('CERT'): -1],
            "Alerte" if "alerte" in entry.link else "Avis", #type
            formatted_date, #data
            cve_id, #CVE
            cvss_score, #CVSS
            severity, #Base Severity
            cwe, #CWE
            description, #CWE Description
            epss_score, #EPSS
            entry.link, #Lien
            entry.description, #Description
            vendor, #Editeur
            product_name, #Produit
            ', '.join(versions) #Versions affectées
            ])



df = pd.DataFrame(dataframe, columns = columns)
df.to_csv('donnees_cybersec.csv', header = True, index = False, mode = 'w', encoding='utf-8')
print("\nConsolidation des données effectuée et exportée dans 'donnees_cybersec.csv'.")


#%% Etape 6 : Génération d'Alertes et Notifications Email
#Modifier pour que l'envoi de mail fonctionne


def send_email(to_email, subject, body):
    from_email = "anonymousatESILV@gmail.com"
    password = "kobu tkmw chvv sxsy"
    
    msg = MIMEText(body)
    msg['From'] = f"CERT-FR <{from_email}>"
    msg['To'] = to_email
    msg['Subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    try :
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
    except Exception as e:
        print("Envoi de mail non effectué :", e)
        
    server.quit()

for i in range(len(df)) :
    if df.loc[i,'Base Severity'] == 'Critical':
        print('Une CVE critique a été détectée. Envoie de mail pour prévenir les utilisateurs !')
        
        title = df.loc[i,'Titre ANSSI']
        send_email("camille.espieux@gmail.com", "Alerte CVE critique", "Mettez à jour votre serveur " + title[title.index('dans') + 5 :] + " immédiatement.")


#%%
print('Fin du programme')
print(f"Programme exécuté en {chronometre(start, time.time())}")