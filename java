server.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Login required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid session' }); }
}

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 864e5 });
  res.json({ email: user.email, role: user.role });
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json(req.user));

app.get('/api/stats', auth, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) c FROM items').get().c;
  const low = db.prepare('SELECT COUNT(*) c FROM items WHERE quantity <= reorder_level').get().c;
  const value = db.prepare('SELECT SUM(quantity * price) v FROM items').get().v || 0;
  const cost = db.prepare('SELECT SUM(quantity * cost) v FROM items').get().v || 0;
  const lowItems = db.prepare('SELECT * FROM items WHERE quantity <= reorder_level ORDER BY quantity').all();
  res.json({ total, low, value, cost, profit: value - cost, lowItems });
});

app.get('/api/items', auth, (req, res) => {
  const { q, low, sort = 'name', dir = 'asc' } = req.query;
  const allowed = ['name','sku','quantity','price','category','updated_at'];
  const col = allowed.includes(sort) ? sort : 'name';
  const d = dir === 'desc' ? 'DESC' : 'ASC';
  let sql = 'SELECT * FROM items WHERE 1=1';
  const params = [];
  if (q) { sql += ' AND (name LIKE ? OR sku LIKE ? OR barcode LIKE ?)'; params.push(`%${q}%`,`%${q}%`,`%${q}%`); }
  if (low === 'true') sql += ' AND quantity <= reorder_level';
  sql += ` ORDER BY ${col} ${d}`;
  res.json({ items: db.prepare(sql).all(...params) });
});

app.post('/api/items', auth, (req, res) => {
  const { name, sku, barcode, category, supplier, quantity, price, cost, reorder_level, location, notes } = req.body;
  try {
    const info = db.prepare(`INSERT INTO items (name,sku,barcode,category,supplier,quantity,price,cost,reorder_level,location,notes)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run(name, sku, barcode, category, supplier, quantity||0, price||0, cost||0, reorder_level||5, location, notes);
    res.json(db.prepare('SELECT * FROM items WHERE id = ?').get(info.lastInsertRowid));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.put('/api/items/:id', auth, (req, res) => {
  const { name, sku, barcode, category, supplier, quantity, price, cost, reorder_level, location, notes } = req.body;
  db.prepare(`UPDATE items SET name=?,sku=?,barcode=?,category=?,supplier=?,quantity=?,price=?,cost=?,
    reorder_level=?,location=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .run(name, sku, barcode, category, supplier, quantity, price, cost, reorder_level, location, notes, req.params.id);
  res.json(db.prepare('SELECT * FROM items WHERE id = ?').get(req.params.id));
});

app.delete('/api/items/:id', auth, (req, res) => {
  db.prepare('DELETE FROM items WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log(`Running on port ${process.env.PORT || 3000}`));
