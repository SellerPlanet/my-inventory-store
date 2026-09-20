javascript
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const db = new Database('inventory.db');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  sku TEXT,
  barcode TEXT,
  category TEXT,
  supplier TEXT,
  quantity INTEGER DEFAULT 0,
  price REAL DEFAULT 0,
  cost REAL DEFAULT 0,
  reorder_level INTEGER DEFAULT 5,
  location TEXT,
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
const admin = db.prepare('SELECT * FROM users WHERE email = ?').get(adminEmail);
if (!admin) {
  db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)')
    .run(adminEmail, bcrypt.hashSync(adminPass, 10), 'admin');
  console.log('Admin created:', adminEmail);
}

module.exports = db;
