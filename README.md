# TP : Audit de Sécurité - "The Broken API"

## Introduction
Bienvenue dans cet exercice de DevSecOps. Vous venez de récupérer le code source d'une API Node.js développée dans l'urgence. Bien que fonctionnelle, cette application est une passoire en termes de sécurité.

**Votre mission :** Infiltrer la peau d'un Pentester (auditeur de sécurité), identifier les vulnérabilités, comprendre leurs impacts et proposer des corrections définitives.

---

## Étape 1 : Mise en place de l'environnement

1.  Forkez ce repo et clonez le.
2.  Initialisez le projet et installez les dépendances nécessaires :
    ```bash
    npm install
    ```
3.  Lancez l'application :
    ```bash
    node server.js
    ```
    *L'API est maintenant accessible sur `http://localhost:3000`.*

---

## Étape 2 : Travail à réaliser

Pour chaque faille trouvée dans le code, vous devez rédiger une fiche d'anomalie structurée comme suit :

### Faille n°X : [Nom de la faille]
* **Localisation :** (Ex: Ligne 15 dans `server.js`)
* **Description :** Expliquez avec vos mots ce qui ne va pas.
* **Exploitation :** Comment un hacker pourrait-il en profiter ? (Exemple de requête ou de manipulation).
* **Impact :** Quel est le risque ? (Vol de données, arrêt du service, usurpation d'identité...).
* **Correction proposée :** Donnez un exemple de code corrigé ou une bonne pratique à appliquer.

---

## Indices : Les 5 vulnérabilités majeures à trouver

Votre audit doit au minimum couvrir les points suivants :

1.  **Gestion des secrets :** Regardez comment l'application gère ses accès "admin".
2.  **Manipulation de la base de données :** Observez la route `/api/user`. Que se passe-t-il si on injecte des caractères spéciaux dans l'URL ?
3.  **Contrôle d'accès :** La route `/api/delete-user` est-elle vraiment protégée ? Le token est-il robuste ?
4.  **Affichage dynamique :** Regardez la route `/api/welcome`. Pouvez-vous forcer l'affichage d'une fenêtre `alert()` dans le navigateur ?
5.  **Fuite d'informations :** Que se passe-t-il si vous provoquez une erreur sur la route `/api/debug` ? Quelles informations le serveur donne-t-il ?

---

## Étape 3 : Sécurisation (Hardening)

Après avoir identifié les failles, modifiez le code pour rendre l'API "Production Ready". 
* **Outils suggérés :** * Utilisez des **requêtes préparées** pour SQLite.
    * Installez le package `dotenv` pour sortir les secrets du code.
    * Explorez la bibliothèque `helmet` pour ajouter des headers de sécurité.
    * Implémentez un système de hashage pour les mots de passe (ex: `bcrypt`).

---

## Livrable
Un rapport au format PDF ou Markdown contenant vos fiches d'anomalies et le repoque vous avez forké du code source final corrigé. Il faudra m'envoyer les 2 en message privé sur Teams.