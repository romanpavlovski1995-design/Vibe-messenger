const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = process.env.JWT_SECRET || 'vibe_secret_key';
const PORT = process.env.PORT || 3000;

const db = new Database(path.join(__dirname, '../vibe.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    nickname TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    avatar_color TEXT DEFAULT '#4fc3f7',
    bio TEXT DEFAULT '',
    online INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conv_key TEXT NOT NULL,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    text TEXT NOT NULL,
    edited INTEGER DEFAULT 0,
    deleted INTEGER DEFAULT 0,
    read_at INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conv_key, created_at);
`);

const convKey = (a, b) => [a, b].sort().join('__');
const COLORS = ['#4fc3f7','#81c784','#ffb74d','#f06292','#ce93d8','#80cbc4','#ff8a65','#90caf9'];
const randomColor = () => COLORS[Math.floor(Math.random() * COLORS.length)];
const clients = new Map();

const sendTo = (username, data) => {
  const conns = clients.get(username);
  if (!conns) return;
  const payload = JSON.stringify(data);
  for (const ws of conns) {
    if (ws.readyState === WebSocket.OPEN) ws.send(payload);
  }
};

const broadcast = (data) => {
  const payload = JSON.stringify(data);
  for (const [, conns] of clients) {
    for (const ws of conns) {
      if (ws.readyState === WebSocket.OPEN) ws.send(payload);
    }
  }
};

wss.on('connection', (ws) => {
  let me = null;
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (msg.type === 'auth') {
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        me = payload.username;
        if (!clients.has(me)) clients.set(me, new Set());
        clients.get(me).add(ws);
        db.prepare('UPDATE users SET online=1, last_seen=? WHERE username=?').run(Date.now(), me);
        broadcast({ type: 'presence', username: me, online: true });
        ws.send(JSON.stringify({ type: 'auth_ok' }));
      } catch { ws.send(JSON.stringify({ type: 'auth_err' })); }
      return;
    }
    if (!me) return;
    if (msg.type === 'message') {
      const to = msg.to?.toLowerCase();
      const text = (msg.text || '').trim().slice(0, 2000);
      if (!to || !text) return;
      const toUser = db.prepare('SELECT username FROM users WHERE username=?').get(to);
      if (!toUser) return;
      const id = uuidv4();
      const ck = convKey(me, to);
      const ts = Date.now();
      db.prepare('INSERT INTO messages(id,conv_key,from_user,to_user,text,created_at) VALUES(?,?,?,?,?,?)').run(id, ck, me, to, text, ts);
      const packet = { type: 'message', id, from: me, to, text, ts, edited: false };
      sendTo(me, packet);
      sendTo(to, packet);
    }
    if (msg.type === 'read') {
      const ck = convKey(me, msg.partner);
      db.prepare('UPDATE messages SET read_at=? WHERE conv_key=? AND to_user=? AND read_at=0').run(Date.now(), ck, me);
      sendTo(msg.partner, { type: 'read', by: me });
    }
    if (msg.type === 'typing') sendTo(msg.to, { type: 'typing', from: me, active: !!msg.active });
    if (msg.type === 'edit') {
      const row = db.prepare('SELECT * FROM messages WHERE id=? AND from_user=?').get(msg.id, me);
      if (!row) return;
      const newText = (msg.text || '').trim().slice(0, 2000);
      if (!newText) return;
      db.prepare('UPDATE messages SET text=?, edited=1 WHERE id=?').run(newText, msg.id);
      const packet = { type: 'edit', id: msg.id, text: newText };
      sendTo(row.from_user, packet);
      sendTo(row.to_user, packet);
    }
    if (msg.type === 'delete') {
      const row = db.prepare('SELECT * FROM messages WHERE id=? AND from_user=?').get(msg.id, me);
      if (!row) return;
      db.prepare('UPDATE messages SET deleted=1, text="" WHERE id=?').run(msg.id);
      const packet = { type: 'delete', id: msg.id };
      sendTo(row.from_user, packet);
      sendTo(row.to_user, packet);
    }
  });
  ws.on('close', () => {
    if (!me) return;
    const conns = clients.get(me);
    if (conns) { conns.delete(ws); if (conns.size === 0) clients.delete(me); }
    if (!clients.has(me)) {
      db.prepare('UPDATE users SET online=0, last_seen=? WHERE username=?').run(Date.now(), me);
      broadcast({ type: 'presence', username: me, online: false, last_seen: Date.now() });
    }
  });
});

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const verifyToken = (req) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
};

app.post('/api/register', (req, res) => {
  const { username, nickname, password } = req.body || {};
  const u = (username || '').toLowerCase().trim();
  if (!/^[a-zA-Z0-9]{4,20}$/.test(u)) return res.status(400).json({ error: 'Username: 4-20 символов, только латиница и цифры' });
  if (!nickname || nickname.length > 30) return res.status(400).json({ error: 'Никнейм: 1-30 символов' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(u)) return res.status(409).json({ error: 'Username уже занят' });
  const hash = bcrypt.hashSync(password, 10);
  const id = uuidv4();
  db.prepare('INSERT INTO users(id,username,nickname,password_hash,avatar_color) VALUES(?,?,?,?,?)').run(id, u, nickname, hash, randomColor());
  const token = jwt.sign({ username: u, id }, JWT_SECRET, { expiresIn: '30d' });
  const user = db.prepare('SELECT username,nickname,avatar_color,bio,online,last_seen,created_at FROM users WHERE username=?').get(u);
  res.json({ token, user });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = (username || '').toLowerCase().trim();
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(u);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Неверный username или пароль' });
  const token = jwt.sign({ username: u, id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  const { password_hash, ...safe } = user;
  res.json({ token, user: safe });
});

app.get('/api/me', (req, res) => {
  const p = verifyToken(req);
  if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const user = db.prepare('SELECT username,nickname,avatar_color,bio,online,last_seen,created_at FROM users WHERE username=?').get(p.username);
  res.json(user);
});

app.patch('/api/me', (req, res) => {
  const p = verifyToken(req);
  if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const { nickname, bio, avatar_color, old_password, new_password } = req.body || {};
  if (nickname) db.prepare('UPDATE users SET nickname=? WHERE username=?').run(nickname.trim().slice(0,30), p.username);
  if (bio !== undefined) db.prepare('UPDATE users SET bio=? WHERE username=?').run(bio.slice(0,150), p.username);
  if (avatar_color) db.prepare('UPDATE users SET avatar_color=? WHERE username=?').run(avatar_color, p.username);
  if (old_password && new_password) {
    const user = db.prepare('SELECT * FROM users WHERE username=?').get(p.username);
    if (!bcrypt.compareSync(old_password, user.password_hash)) return res.status(400).json({ error: 'Старый пароль неверный' });
    if (new_password.length < 4) return res.status(400).json({ error: 'Новый пароль минимум 4 символа' });
    db.prepare('UPDATE users SET password_hash=? WHERE username=?').run(bcrypt.hashSync(new_password, 10), p.username);
  }
  const user = db.prepare('SELECT username,nickname,avatar_color,bio,online,last_seen,created_at FROM users WHERE username=?').get(p.username);
  res.json(user);
});

app.get('/api/users/search', (req, res) => {
  const p = verifyToken(req);
  if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const q = (req.query.q || '').toLowerCase().trim();
  if (!q) return res.json([]);
  const rows = db.prepare("SELECT username,nickname,avatar_color,bio,online,last_seen FROM users WHERE username LIKE ? AND username != ? LIMIT 10").all(`${q}%`, p.username);
  res.json(rows);
});

app.get('/api/users/:username', (req, res) => {
  const p = verifyToken(req);
  if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const user = db.prepare('SELECT username,nickname,avatar_color,bio,online,last_seen,created_at FROM users WHERE username=?').get(req.params.username.toLowerCase());
  if (!user) return res.status(404).json({ error: 'Не найден' });
  res.json(user);
});

app.get('/api/messages/:partner', (req, res) => {
  const p = verifyToken(req);
  if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const ck = convKey(p.username, req.params.partner.toLowerCase());
  const before = req.query.before ? parseInt(req.query.before) : Date.now() + 1000;
  const rows = db.prepare('SELECT id,from_user,to_user,text,edited,deleted,read_at,created_at FROM messages WHERE conv_key=? AND created_at<? ORDER BY created_at DESC LIMIT 50').all(ck, before);
  res.json(rows.reverse());
});

app.get('/api/conversations', (req, res) => {
  const p = verifyToken(req);
  if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const rows = db.prepare(`
    SELECT m.conv_key, m.from_user, m.to_user, m.text, m.deleted, m.created_at,
    (SELECT COUNT(*) FROM messages m2 WHERE m2.conv_key=m.conv_key AND m2.to_user=? AND m2.read_at=0) as unread
    FROM messages m
    WHERE (m.from_user=? OR m.to_user=?)
    AND m.created_at = (SELECT MAX(created_at) FROM messages WHERE conv_key=m.conv_key)
    GROUP BY m.conv_key
    ORDER BY m.created_at DESC
  `).all(p.username, p.username, p.username);
  const result = rows.map(row => {
    const partner = row.from_user === p.username ? row.to_user : row.from_user;
    const user = db.prepare('SELECT username,nickname,avatar_color,online,last_seen FROM users WHERE username=?').get(partner);
    return { ...row, partner: user };
  }).filter(r => r.partner);
  res.json(result);
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

server.listen(PORT, () => console.log(`✅ Vibe запущен на http://localhost:${PORT}`));
