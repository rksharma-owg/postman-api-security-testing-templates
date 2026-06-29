
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true })); // Intentionally weak CORS for lab practice.

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER, email TEXT, role TEXT)');
  db.run("INSERT INTO users VALUES (1, 'alice@example.test', 'user')");
  db.run("INSERT INTO users VALUES (2, 'admin@example.test', 'admin')");
});

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok', lab: 'node' }));

app.get('/api/v1/users', (req, res) => {
  const q = req.query.q || '';
  // Intentionally vulnerable SQL concatenation for local practice only.
  db.all("SELECT id, email, role FROM users WHERE email LIKE '%" + q + "%'", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: rows });
  });
});

app.get('/api/v1/admin/users', (req, res) => {
  // Intentionally broken access control for lab practice.
  res.json({ users: [{ id: 1, email: 'alice@example.test' }, { id: 2, email: 'admin@example.test' }] });
});

app.listen(8081, () => console.log('Node vulnerable API listening on 8081'));
