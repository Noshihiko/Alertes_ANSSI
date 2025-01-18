Projet de Récupération, Traitement et Notification des Alertes ANSSI

Objectif :
Le but principal de ce projet est d'automatiser la récupération d'alertes de sécurité (avis et alertes) émises par l'ANSSI et de notifier les utilisateurs potentiellement affectés en fonction de leurs préférences et des vulnérabilités identifiées.

Prérequis d'installation : Aucun, les bibliothèques nécessaires sont directement importées dans votre IDE.

Structure du projet :
- projetv4.py : Le script principal qui exécute le programme.
- images/ : Dossier contenant les images utilisées dans les emails.
- data/ : Dossier contenant les différents fichiers de données nécessaires pour une bonne exécution du programme.
	- users.csv : Fichier contenant les informations des utilisateurs (email, préférences, logiciels) :
		Pour rajouter des utilisateurs, simplement aller à la ligne et respecter l'écriture du premier utilisateur :
		adresse_mail,Logiciel1-Logiciel2-...-LogicielN,TYPE1-...-TYPEN
		Le type peut être NONE, LOW, MEDIUM, HIGH, CRITICAL et ALL.
	
	- feed.csv : Fichier contenant les liens des flux RSS et leurs dates de dernière récupération.
		Si vous cherchez à vérifier que l'algorithme fonctionne, veuillez d'abord à regarder si la date de récupération des flux RSS dans le fichier ne correspond pas déjà à la dernière date de mise à jour sur le site. Sans cette vérification, vous risquez de ne récupérer aucune entrée.
	
	- donnees_cybersec.csv : Fichier contenant l'ensemble des alertes et avis du site de l'ANSSI. NE PAS TOUCHER.

Point de vigilence :
Lors du premier lancement du programme, votre machine peut indiquer ne pas trouver les fichiers aux chemins d'accès renseignés. Votre machine ne cherche pas les fichiers au bon endroit.
Veuillez s'il vous plaît rajouter ces lignes de code en début du programme pour indiquer à la machine où les récupérer : 

import os
# Chemin absolu du nouveau répertoire de travail
new_working_directory = r""

# Changer le répertoire courant
os.chdir(new_working_directory)

Veuillez à mettre le chemin d'accès qui mène au contenu du dossier du projet, nommé "Projet", dans les "" de la variable new_working_directory.

Vidéo réalisée sur Canva. Si le mp4 ne fonctionne pas, vous pouvez la visionner au lien suivant :
https://www.canva.com/design/DAGcjl92Tds/030gckNti1Ik_9mSAH8doA/watch?utm_content=DAGcjl92Tds&utm_campaign=designshare&utm_medium=link2&utm_source=uniquelinks&utlId=hda551ef468