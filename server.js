require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const { body, query, validationResult } = require('express-validator');

const app = express();
app.use(helmet());
app.use(bodyParser.json());

// Base de données en mémoire pour l'exo (pour tests). En prod, utiliser une BD persistante.
const db = new sqlite3.Database(':memory:');

// Charger le token d'admin depuis les variables d'environnement
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'CHANGE_ME_PLEASE';

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)');
  const insert = db.prepare('INSERT OR IGNORE INTO users (id, username, password, role) VALUES (?, ?, ?, ?)');
  const hashedAdmin = bcrypt.hashSync('password123', 10);
  const hashedUser = bcrypt.hashSync('azerty', 10);
  insert.run(1, 'admin', hashedAdmin, 'admin');
  insert.run(2, 'user1', hashedUser, 'user');
  insert.finalize();
});

// Middleware pour vérifier erreurs de validation
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  next();
}

// Récupération d'un utilisateur - requête paramétrée
app.get('/api/user', [query('username').isString().notEmpty()], handleValidationErrors, (req, res) => {
  const username = req.query.username;
  const sql = 'SELECT id, username, role FROM users WHERE username = ?';
  db.get(sql, [username], (err, row) => {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }
    if (!row) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    return res.json(row);
  });
});

// Middleware d'authentification admin simple (Bearer token)
function checkAdmin(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifié' });
  const token = auth.slice(7).trim();
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'Accès refusé' });
  next();
}

app.post('/api/delete-user', checkAdmin, [body('id').isInt({ min: 1 })], handleValidationErrors, (req, res) => {
  const id = parseInt(req.body.id, 10);
  db.run('DELETE FROM users WHERE id = ?', [id], function (err) {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }
    if (this.changes === 0) return res.status(404).json({ error: 'Utilisateur introuvable' });
    return res.json({ ok: true, message: 'Utilisateur supprimé' });
  });
});

// Endpoint welcome renvoyant JSON (évite XSS)
app.get('/api/welcome', (req, res) => {
  const name = req.query.name ? escapeHtml(req.query.name) : 'Visiteur';
  return res.json({ message: `Bienvenue sur l'API, ${name} !` });
});

// Debug endpoint sécurisé : ne pas exposer d'informations sensibles
app.get('/api/debug', (req, res) => {
  try {
    throw new Error('Simulated internal error');
  } catch (err) {
    console.error('Internal error (debug):', err.message);
    return res.status(500).json({ error: 'Erreur interne' });
  }
});

// Export app pour tests
module.exports = app;

// Lancer le serveur seulement si ce fichier est exécuté directement
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`🚀 API hardenée lancée sur http://localhost:${port}`));
}