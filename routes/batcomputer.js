const express = require('express');
const fs = require('fs');
const path = require('path');
const { stmts } = require('../config/db');
const { checkJWT } = require('../middlewares/authCheck');

const router = express.Router();

const DASHBOARD_VIEW = path.join(__dirname, '..', 'views', 'bat-computer.html');
const asString = (v) => (v ?? '').toString();

const GADGETS = [
  { name: 'Batarang', desc: 'Arme de jet', icon: 'fa-shuriken' },
  { name: 'Grappin', desc: 'Deplacement vertical', icon: 'fa-anchor' },
  { name: 'Bat-Signal', desc: "Communication d'urgence", icon: 'fa-bullhorn' },
  { name: 'Smoke Pellets', desc: 'Esquive tactique', icon: 'fa-cloud' },
  { name: 'Cles Batmobile', desc: 'Vehicule blinde', icon: 'fa-car' },
  { name: 'Gel Explosif', desc: 'Demolition controlee', icon: 'fa-bomb' }
];

// Tableau de bord protégé : le nom de l'agent vient du payload du jeton, pas de la RAM.
router.get('/bat-computer', checkJWT, (req, res) => {
  const html = fs.readFileSync(DASHBOARD_VIEW, 'utf-8')
    .replaceAll('{{username}}', req.user.username);
  res.send(html);
});

router.get('/api/secrets', checkJWT, (req, res) => {
  res.json(GADGETS);
});

router.get('/api/me', checkJWT, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
});

router.post('/api/reports', checkJWT, (req, res) => {
  const content = asString(req.body.content).trim();
  if (!content) {
    return res.status(400).json({ error: 'Le rapport ne peut etre vide.' });
  }
  const info = stmts.insertReport.run(req.user.id, content);
  return res.status(201).json({ id: info.lastInsertRowid, user_id: req.user.id, content });
});

module.exports = router;
