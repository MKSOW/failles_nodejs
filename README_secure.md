# README_secure — Déploiement sécurisé de l'API

Ce document explique comment déployer l'API en production de façon sécurisée.

Prérequis
- Node.js 18+ / 20+
- Un gestionnaire de secrets pour la prod (Vault, AWS Secrets Manager, Azure Key Vault...)
- Certificat TLS (Let’s Encrypt / ACME / CA interne)

Étapes rapides pour l'environnement de développement
1. Copier `.env.example` en `.env` et définir `ADMIN_TOKEN` :

```bash
cp .env.example .env
# Éditer .env et remplacer ADMIN_TOKEN par une valeur forte
```

2. Installer les dépendances et lancer :

```bash
npm install
npm start
```

Le serveur écoute sur `http://localhost:3000` (ou `PORT` défini dans `.env`).

Sécurité (production)
- Secrets : ne pas stocker de secrets dans le code. Utiliser un gestionnaire de secrets et monter les variables d'environnement au démarrage.
- HTTPS : exposer l'API via un reverse-proxy (nginx) ou via une plateforme qui gère TLS. Configurer HSTS.
- Headers : utiliser `helmet` (déjà inclus) pour ajouter des headers de sécurité.
- Auth : utiliser JWT signés avec expiration et rotation des clés, ou un système d'authentification centralisé (OAuth2/OpenID Connect).
- Rate-limiting : ajouter `express-rate-limit` pour limiter les abus.
- Logging & Audit : centraliser les logs, journaliser les actions administratives (qui a supprimé quel utilisateur).
- Tests : lancer des tests automatiques et des scans (OWASP ZAP) après chaque déploiement.

Bonnes pratiques de CI/CD
- Ne pas injecter `.env` dans le dépôt.
- Exécuter lint, tests et scans de sécurité avant déploiement.
- Déployer avec des conteneurs immuables et rollback rapide.

Contact
- Auteur du hardening : (à renseigner)
