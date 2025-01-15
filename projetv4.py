# -*- coding: utf-8 -*-
"""
Created on Fri Dec 27 17:10:17 2024

@authors: anonyme1, anonyme2, anonyme3
"""
import feedparser, requests, re, pandas as pd, smtplib, os
from datetime import datetime, timedelta
from time import sleep
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage

# Chemin absolu du nouveau répertoire de travail
# new_working_directory = #attention veuillez indiquer le chemin d'accès vers l'endroit où est téléchargé le fichier si le programme ne trouve pas les différents csv
# os.chdir(new_working_directory)

# # Vérifier le changement
# print("Nouveau répertoire courant :", os.getcwd())

def recuperer_donnees(link):
    """
    Récupère et retourne les données JSON depuis un lien "link" donné
    
    
    Paramètre : 
        link (str) : URL du lien dont on souhaite récupérer les données
    
    Retourne :
        dict : les données JSON obtenues
        None : en cas d'erreur
    """
    try :
        sleep(1)
        response = requests.get(link)
        return response.json()
    except Exception as e:
        print(f"Erreur d'accès à {link} :\n{e}")
        return None

def chronometre(start, end):
    """
    Calcule la durée entre deux dates de type datetime données
    
    
    Paramètres :
        start (datetime) : date de début
        end (datetime) : date de fin
    
    Retourne :
        str : la durée entre les deux dates formatées
    """
    return f"Durée : {end - start}"

def recuperer_feed(feed_recupere, url, feed):
    feed_recupere = []
    """
    Récupère les flux RSS à partir des liens contenues dans le tableau "url" et les ajoute à une liste
    
    
    Paramètres :
        feed_recupere (list) : liste où sont stockées les entrées des flux RSS
        url (list) : liste d'URL dont on souhaite extraire les données
        feed (DataFrame) : dataframe contenant les liens de l'ensemble des flux récupérés et leur dernière date de récupération
    
    Retourne :
        feed_recupere (list) : liste des entrées des flux RSS récupérées
        feed (DataFrame) : DataFrame mis à jour avec les liens et les dates de récupération des flux RSS
    """
    print("\n\nEtape 1 - Récupération des flux RSS en cours...")
    for link in url :
        print("\n"+link)
        data = feedparser.parse(link)
        sleep(2)

        date_maj = datetime.strptime(data.updated, "%a, %d %b %Y %H:%M:%S GMT")
        print(f"Date dernière maj du flux par l'ANSSI : {date_maj}")
        
        if link in feed['lien'].values :
            print("Flux contenu dans le fichier 'feed.csv'")
            date_feed = feed.loc[feed['lien'] == link, 'date_recuperee'].iloc[0]
            print(f"Date dernière maj du flux dans le fichier 'feed.csv': {date_feed}")
            
            if not pd.isna(date_feed):
                date_feed = datetime.strptime(date_feed, "%Y-%m-%d %H:%M:%S")
                
            if pd.isna(date_feed) or date_maj - date_feed >= timedelta(minutes= 5):
                feed_recupere.extend(data.entries)
                print("Récupération fini du flux.\n\n")
            else :
                print("Récupération non effectué car la dernière maj du flux est trop récente.\n\n")
            feed.loc[feed['lien'] == link, 'date_recuperee'] = date_maj.strftime("%Y-%m-%d %H:%M:%S")
        else :  
            feed_recupere.extend(data.entries)
            new_row = pd.DataFrame({'lien': [link], 'date_recuperee': [date_maj.strftime('%Y-%m-%d %H:%M:%S')]})
            feed = pd.concat([feed, new_row], ignore_index=True)
            print("Récupération fini du flux.\n\n")
        
    print(f"\nEtape 1 effectuée. {len(feed_recupere)} entrées récupérées.")
    return feed_recupere, feed
    

def extraction_cves_bis(rss_feed):
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

def extraction_cves(rss_feed):
    """
    Extrait les identifiants CVE de chaque alerte et avis contenus dans les flux RSS récupérés
    Produit un fichier CSV contenant les références ANSSI désormais analysées (pour ne pas les réexploiter)

    
    Paramètre :
        rss_feed (list) : liste d'entrées (avis ou alertes ANSSI)
    
    Retourne :
        all_CVE (list) : liste pour stocker les listes de CVE extraites par entrée
    """
    print('\n\nEtape 2 : Extraction des CVE en cours...')
    all_CVE = []
    for entry in rss_feed :
        try :
            data = recuperer_donnees(entry.link +'json/')            
            ref_cves=list(data["cves"])
            #attention il s’agit d’une liste des dictionnaires avec name et url comme clés
            print( "CVE référencés ", ref_cves)

            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cve_list = list(set(re.findall(cve_pattern, str(data))))
            
            all_CVE.append(cve_list)
        except Exception as e :
            print(f"Erreur d'accès au lien JSON de l'entrée : {e}")
    
    print(f"\nEtape 2 effectuée. {sum([len(x) for x in all_CVE])} CVE extraites.")
    return all_CVE

def avis_email(df):
    """
    Construction et envoie d'emails contenant les avis et alertes critiques datant de moins de deux semaines
    Affiche également le nombre d'emails correctement envoyés (et le nombre d'échecs)
    
    
    Paramètres :
        df (DataFrame) : données des CVE consolidées utilisées pour l'envoi de mail et la personnalisation du corps de ce dernier
        to_email (list) : liste d'adresses email des destinataires
    """
    users = pd.read_csv('data\\users.csv', sep=',')
    
    intervalle = datetime.now() - timedelta(weeks=2)
    entrees_recentes = df[(pd.to_datetime(df['Date']) >= intervalle)]
    print(len(entrees_recentes))
    echec = 0
    reussite = 0

    for _, line in entrees_recentes.iterrows():
        #Création d'un email perso en fonction des caractèristiques de la CVE et de son entrée associée
        type_entree = "nulle"
        if line['Sévérité'] == 'CRITICAL' :
            type_entree = "critique"
        elif line['Sévérité'] == 'HIGH':
            type_entree = "haute"
        elif line['Sévérité'] == 'MEDIUM':
            type_entree = "moyenne"
        elif line['Sévérité'] == 'LOW':
            type_entree = "faible"
            
        message_perso = f"Un nouvel <strong>avis de sévérité {type_entree}</strong> a été détecté" if line['Type'] == 'Avis' else f"Une nouvelle <strong>alerte de sévérité {type_entree}</strong> a été détectée"
        
        subject = f"[URGENT ANSSI] {line['Référence ANSSI']} - {line['Titre ANSSI']}"
        body_html = f"""
        
        <html>
        <body style="font-family: Arial, sans-serif; color: #000000;">
            <p>Bonjour,</p>
            <p>{message_perso} par l'ANSSI le {line['Date']} :</p>
            <ul>
                <li><strong>Référence ANSSI :</strong> {line['Référence ANSSI']}</li>
                <li><strong>Titre :</strong> {line['Titre ANSSI']}</li>
                <li><strong>CVE critique :</strong> {line['CVE']}</li>
                <li><strong>Produit :</strong> {line['Produit']} (Versions affectées : {line['Versions affectées']})</li>
                <li><strong>Description :</strong> {line['Description']}</li>
            </ul>
            <p>Pour plus d'informations, consultez le lien suivant : 
                <a href="{line['Lien']}" style="color: #004a9f;">{line['Lien']}</a>
            </p>
            <p style="font-weight: bold; color: #d9534f;">Prenez des mesures immédiates : mettez à jour l'application sur le site officiel du logiciel !</p>
            <div style="display: flex; align-items: center; margin-top: 20px;">
                <img src="cid:logo" style="width: 202px; margin-right: 15px;">
                <div>
                    <p>
                        <strong>Agence nationale de la sécurité des systèmes d'information</strong><br>
                        - En France métropolitaine : <strong>3218</strong> (service gratuit + prix d’un appel) ou <strong>09 70 83 32 18</strong><br>
                        - En Outre-mer ou depuis l’étranger : <strong>+33 9 70 83 32 18</strong><br>
                        51, boulevard de La Tour-Maubourg<br>
                        75700 PARIS 07
                    </p>
                    <p style="font-size: 0.9em; color: #666;">
                        Merci de ne pas répondre directement à ce mail. Si besoin, contactez-nous à :
                        <a href="mailto:cert-fr@ssi.gouv.fr" style="color: #004a9f;">cert-fr@ssi.gouv.fr</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        print(line['Produit'], line['Sévérité'])
        for _, user in users.iterrows():
            user_mail = user['mail']
            user_logiciels = user['logiciels'].split('-')
            user_preference = user['preference'].split('-')
            if "ALL" in user_preference :
                user_preference = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            # Vérification que le logiciel et la sévérité correspondent
            if any(log in line['Produit'] for log in user_logiciels) and any(sev in line['Sévérité'] for sev in user_preference):
                print("in the if")
                # Envoi de l'email
                boolean = send_email(user_mail, subject, body_html, line['CVE'])
                if boolean:
                    reussite += 1
                else:
                    echec += 1

    print(f"{reussite} mails envoyés - {echec} échecs")

def send_email(to_email, subject, body_html, cve_id):
    """
    Création de l'email et lien avec le serveur gmail pour envoyer l'email à l'utilisateur
    Affiche également si le mail a bien été envoyé pour la CVE "cve_id" à l'utilisateur "to_email"
    
    Paramètres :
        to_email (str) : email du destinataire
        subject (str) : objet de l'email
        body_html (str) : contenu HTML de l'email créé dans avis_email(df, to_email)()
        cve_id (str) : identifiant du CVE associé pour la customisation des champs
    
    Retourne :
        bool : True si envoi effectué, False sinon
    """
    from_email = "anonymousatESILV@gmail.com"
    password = "kobu tkmw chvv sxsy"
    image_path = "images\\ANSSI_Logo.png"
    
    try:
        # Création du message avec pièces jointes
        msg = MIMEMultipart("related")
        msg["From"] = f"ANSSI - CERT-FR <{from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["X-Priority"] = "1"
        msg["Importance"] = "high"

        # Partie HTML
        body = MIMEText(body_html, "html")
        msg.attach(body)

        # Ajout de l'image
        with open(image_path, "rb") as img_file:
            img = MIMEImage(img_file.read())
            img.add_header("Content-ID", "<logo>")
            msg.attach(img)

        # Connexion et envoi
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        print(f"Email envoyé avec succès pour l'avis critique : {cve_id} à {to_email}")
        server.quit()
        return True

    except Exception as e:
        print(f"Envoi de mail non effectué pour {cve_id} : {e}")
        return False

def enrichissement_cve(all_CVE, df_initial):
    print("\n\nEtape 3 : Enrichissement des CVE...")
    
    for m in range(len(all_CVE)):
        for cve_id in all_CVE[m] :
            print(f'\n\n\nCVE : {cve_id}')
            data1 = recuperer_donnees(f"https://cveawg.mitre.org/api/cve/{cve_id}")
            cve_data = data1.get('containers')
            
            if not cve_data :
                print(f"Données non existantes pour la CVE : {cve_id}")
                continue
            
            entry = rss_feed[m]
            title = entry['title']
            title = title[: title.index('(') - 1]
            reference = entry.link[entry.link.index('CERT'): -1]
            
            date_str = data1.get("cveMetadata").get("dateUpdated")
            try: #try and except car les dates n'ont pas toutes le même format...
                date_last_update = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                date_last_update = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")

            #Vérification si la CVE existe déjà dans le fichier 'donnees_cybersec.csv' pour déterminer s'il faut la traiter ou non
            if cve_id in df_initial['CVE'].values :
                print(f"{cve_id} contenu dans le fichier 'donnees_cybersec.csv'")
                
                ref_anssi = df_initial.loc[df_initial['CVE'] == cve_id, 'Référence ANSSI'].tolist() #transformer en liste car plusieurs avis/alertes peuvent avoir la même CVE
                
                if reference in ref_anssi :
                    print(reference)
                    print("CVE et Ref ANSSI trouvés dans le fichier d'origine : Vérification si les informations sont à jour")
                    
                    date_recuperee = df_initial.loc[(df_initial['CVE'] == cve_id) & (df_initial['Référence ANSSI'] == reference), 'Date'].iloc[0]
                    if isinstance(date_recuperee, str):
                        date_recuperee = datetime.strptime(date_recuperee, "%Y-%m-%d %H:%M:%S.%f")
                    elif isinstance(date_recuperee, pd.Timestamp):
                        date_recuperee = date_recuperee.to_pydatetime()

                    print(f'Date de la dernière maj de cette CVE-Ref ANSSI dans le fichier d\'origine : {date_recuperee}')   
                    print(f'Date de la dernière maj sur mitre : {date_last_update}')
                    
                    if date_recuperee >= date_last_update  :  #cas dans la bdd et à jour
                        print("La CVE avec la ref ANSSI sont déjà à jour dans le fichier d'origine : aucune action supplémentaire")
                        continue
                    else : #cas dans la bdd et pas à jour : suppression de la ligne pour la retraiter
                        df_initial = df_initial.drop(df_initial[(df_initial['CVE'] == cve_id) & (df_initial['Référence ANSSI'] == reference)].index)
                        print("Pas à jour : ligne supprimée pour futur traitement")
                        df_initial.reset_index(drop=True, inplace=True)  # Réinitialisation de l'index après suppression
            
            description = "Non disponible"   
            vendor = "Non disponible"
            product_name = "Non disponible"
            versions = "Non disponible"
            cwe = "Non disponible"
            cwe_desc = "Non disponible"
            severity = "None"
            cvss_score = 0
            
            donnee_CNA = cve_data.get("cna")
            donnee_ADP = cve_data.get("adp")
            
            if donnee_CNA :
                
                #extraction description
                description = donnee_CNA.get("descriptions")
                if description :
                    description = description[0].get("value", "Non disponible")
                
                
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
                if affected :
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
                if not affected or vendor == "n/a" or product == "n/a" or "n/a" in versions :
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
            print(date_last_update)
            
            #Ajout des infos récupérées au dataframe
            new_row = {
                'Titre ANSSI': title,
                'Référence ANSSI': reference,
                'Type': "Alerte" if "alerte" in entry.link else "Avis",
                'Date': date_last_update,
                'CVE': cve_id,
                'CVSS': 0 if severity.upper() == "NONE" or not cvss_score else cvss_score,
                'Sévérité': "NONE" if cvss_score == 0 or not severity else severity.upper(),
                'CWE': cwe,
                'Description': description,
                'EPSS': epss_score,
                'Lien': entry.link,
                'Editeur': "Non disponible" if vendor == "n/a" else vendor,
                'Produit': "Non disponible" if product_name == "n/a" else product_name,
                'Versions affectées': "Non disponible" if versions == [] or "n/a" in versions else ', '.join(versions)
            }
            df_initial = pd.concat([df_initial, pd.DataFrame([new_row])], ignore_index=True)
            print(f"Données ajoutées pour CVE : {cve_id}")
            
    print("Etape 3 finie")
    return df_initial


#%%
print("Lancement du programme")
start = datetime.now()

feed = pd.read_csv('data\\feed.csv', sep = '-')
df_initial = pd.read_csv('data\\donnees_cybersec.csv')

url = ["https://www.cert.ssi.gouv.fr/alerte/feed","https://www.cert.ssi.gouv.fr/avis/feed"] 
rss_feed = []

#Etape 1
print("RSS Feed avant récupération:", rss_feed)
rss_feed, feed = recuperer_feed(rss_feed, url, feed)
print("RSS Feed après récupération:", rss_feed)
print("DataFrame Feed:", feed.head())


feed.to_csv('data\\feed.csv', header = True, index = False, mode = 'w', encoding='utf-8', sep = '-')

#Etape 2
all_CVE = extraction_cves(rss_feed)
all_CVE_bis = extraction_cves_bis(rss_feed)

#Etapes 3 et 4
df_initial = enrichissement_cve(all_CVE, df_initial)
df_initial.to_csv('data\\donnees_cybersec.csv', header = True, index = False, mode = 'w', encoding='utf-8')

print("\nConsolidation des données effectuée et exportée dans 'data\\donnees_cybersec.csv'.")
#%%
#Etape 6
avis_email(df_initial)

print('Fin du programme')
print(f"Programme exécuté en {chronometre(start, datetime.now())}")

#%%
print(sum([len(x) for x in all_CVE]))