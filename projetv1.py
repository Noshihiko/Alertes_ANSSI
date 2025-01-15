# -*- coding: utf-8 -*-
"""
Created on Fri Dec 27 17:10:17 2024

@author: anonyme
"""
#%%
import feedparser
import requests
import re
import pandas as pd
import smtplib
from datetime import datetime
from time import sleep
from email.mime.text import MIMEText

#%%
def recuperer_donnees(link): 
    sleep(0.5)
    response = requests.get(link)
    data = response.json()
    return data

#%% Etape 1 bis
print("Etape 1 en cours ....")
url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
rss_feed = feedparser.parse(url_avis)
sleep(2)

#%% Etape 1
print("Etape 1 en cours ....")
url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
rss_avis = feedparser.parse(url_avis)
sleep(2)
#print(rss_avis)
#print(len(rss_avis.entries))
rss_feed = rss_avis.entries

url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed"
rss_alerte = feedparser.parse(url_alerte)
rss_feed.extend(rss_alerte.entries)
#print(len(rss_feed))
sleep(2)
#print(rss_feed)
#%% Etape 2
print('Etape 2 en cours ....')
all_CVE = []
for entry in rss_feed.entries :
    data = recuperer_donnees(entry.link +'json/')
    
    #Extraction des CVE reference dans la clé cves du dict data
    ref_cves=list(data["cves"])
    #attention il s’agit d’une liste des dictionnaires avec name et url comme clés
    #print("CVE référencés ", ref_cves)
    
    # Extraction des CVE avec une regex
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_list = list(set(re.findall(cve_pattern, str(data))))
    #print("CVE trouvés :", cve_list)
    all_CVE.append(cve_list)
# print(all_CVE) 

CVE_exploitable = [y for x in all_CVE for y in x]
#print(CVE_exploitable) 

cve_id = "CVE-2024-43834"
url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
response = requests.get(url)
data = response.json()
cvss_score = data["containers"]["cna"].get("metrics",None)
#print(cvss_score, '\n\n')
if cvss_score != None :
    #print(cvss_score[0].keys())
    k = cvss_score[0].keys()
    key = None
    for i in k:
        if 'cvss' in i:
            key = i
    if key != None :   
        cvss_score = cvss_score[0].get(key, None).get('baseScore', None)
#print(cvss_score)

#%% Etapes 3 & 4 :
print("Etapes 3 et 4 en cours....")
df = [[] for i in range(14)]

for cve_id in CVE_exploitable :
    donnee = recuperer_donnees(f"https://cveawg.mitre.org/api/cve/{cve_id}").get('containers', None)
    
    description = None   
    vendor = None
    product_name = None
    versions = []
    cwe = "Non disponible" #Demander si on peut remplacer Non disp par None pour Jupyter ensuite
    cwe_desc= "Non disponible" #à quoi ça sert ?
    severity = 'None'
    cvss_score = 0
    
    if donnee != None :
        donnee_CNA = donnee.get('cna', None)
        if donnee_CNA != None :
            description = donnee_CNA.get("descriptions",None)
            cvss_score = donnee_CNA.get("metrics", 0)
            
            #extraction description
            if description != None :
                description = description[0].get('value', None)
                #print(description)
            
            #extraction score cvss
            if cvss_score != 0:
                k = cvss_score[0].keys()
                key = None
                for i in k:
                    if 'cvss' in i:
                        key = i
                if key != None :   
                    cvss_score = cvss_score[0].get(key, 0).get('baseScore', 0)
                    severity = cvss_score[0].get(key, 0).get('baseSeverity', "None").title()
                else:
                    cvss_score = 0
    
            #extraction type de problèmes
            problemtype = donnee_CNA.get("problemTypes", {})
            #print(problemtype)
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
                
            #extraction produits affectés
            affected = donnee_CNA.get("affected", None)
            if affected != None:
                for product in affected:
                    vendor = product.get("vendor", None)
                    product_name = product.get("product", None)
                    if 'versions' in product.keys():
                        versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                    else :
                        versions = []
                    #print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
            else :
                vendor = None
                product_name = None
                versions = []
   
        if cvss_score == 0:
            
            donnee_ADP = donnee.get('adp', 0)
            if donnee_ADP != 0 :
                
                cvss_score = donnee_ADP[0].get('metrics', 0)
                if cvss_score != 0:
                    
                    k = cvss_score[0].keys()
                    key = None
                    for i in k:
                        if 'cvss' in i:
                            key = i
                    if key != None :   
                        cvss_score = cvss_score[0].get(key, 0).get('baseScore', 0)
                        severity =  cvss_score[0].get(key, 0).get('baseSeverity', "None").title()
                    else:
                        cvss_score = 0
    
    # Extraire le score EPSS
    epss_data = recuperer_donnees(f"https://api.first.org/data/v1/epss?cve={cve_id}").get("data", [])
    epss_score = None
    if epss_data != []:
        epss_score = epss_data[0].get("epss", None)
    
    
    # if cvss_score == 0:
    #     severity = 'None'
    # elif 0.1 <= cvss_score <= 3.9:
    #     severity = 'Low'
    # elif 4.0 <= cvss_score <= 6.9:
    #     severity = 'Medium'
    # elif 7.0 <= cvss_score <= 8.9:
    #     severity = 'High'
    # else :
    #     severity = 'Critical'
    
    #Création du df : récupérable
    entry = None
    for x in range(len(all_CVE)) :
        if cve_id in all_CVE[x] :
            entry = rss_feed.entries[x]
    #print(entry)
    title = entry['title']
    title = title[: title.index('(') - 1]
    
    dt = datetime.strptime(entry.published, "%a, %d %b %Y %H:%M:%S %z")
    formatted_date = dt.strftime("%Y-%m-%d")
    
    df[0].append(title) #titre ANSSI
    df[1].append(entry.link[entry.link.index('CERT'): -1])
    df[2].append('Avis' if 'avis' in entry.link else 'Alerte') #type
    df[3].append(formatted_date) #data
    df[4].append(cve_id) #CVE
    df[5].append(cvss_score) #CVSS
    df[6].append(severity) #Base Severity
    df[7].append(cwe) #CWE
    df[8].append(epss_score) #EPSS
    df[9].append(entry.link) #Lien
    df[10].append(description) #Description
    df[11].append(vendor) #Editeur
    df[12].append(product_name) #Produit
    df[13].append(', '.join(versions) if versions != [] else '') #Versions affectées #à voir si on peut pas juste mettre le truc sans le if

# URL de l'API EPSS pour récupérer la probabilité d'exploitation
cve_id = "CVE-2023-46805"
url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
# Requête GET pour récupérer les données JSON

response = requests.get(url)
data = response.json()
# Extraire le score EPSS
epss_data = data.get("data", [])
if epss_data:
    epss_score = epss_data[0]["epss"]
    print(f"CVE : {cve_id}")
    print(f"Score EPSS : {epss_score}")
else:
    print(f"Aucun score EPSS trouvé pour {cve_id}")

#%% Etape 4 : Consolidation des données :
print("Fin étape 4 en cours....")
columns = ['Titre ANSSI', 'Référence ANSSI', 'Type', 'Data', 'CVE', 'CVSS', 'Base Severity', 'CWE', 'EPSS', 'Lien', 'Description', 'Editeur', 'Produit', 'Versions affectées']

data = dict(zip(columns, df))
df_export = pd.DataFrame(data)

#print('Taille du df :', df_export.shape)
print(df_export.head(1))

df_export.to_csv('C:\\Users\\camil\\OneDrive - De Vinci\\Esilv\\S5 - A3\\Langage Python\\Projet\\donnees_cybersec.csv', header = True, index = False, mode = 'w', decimal = '.', encoding='utf-8')
    

#%% Etape 6 : Génération d'Alertes et Notifications Email
#Modifier pour que l'envoi de mail fonctionne


def send_email(to_email, subject, body):
    from_email = "votre_email@gmail.com"
    password = "mot_de_passe_application"
    msg = MIMEText(body)
    
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

# for i in range(len(df)) :
#     if df.loc[i,'Base Severity'] == 'Critical':
#         title = df.loc[i,'Titre ANSSI']
#         send_email("destinataire@email.com", "Alerte CVE critique", "Mettez à jour votre serveur " + title[title.index('dans') + 5 :] + " immédiatement.")

