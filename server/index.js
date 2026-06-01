const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = process.env.JWT_SECRET || 'vibe_secret_key';
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join('/tmp', 'vibe_db.json');

function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
  return { users: {}, messages: {} };
}
function saveDB(db) { try { fs.writeFileSync(DB_FILE, JSON.stringify(db)); } catch {} }

const convKey = (a, b) => [a, b].sort().join('__');
const COLORS = ['#4fc3f7','#81c784','#ffb74d','#f06292','#ce93d8','#80cbc4','#ff8a65','#90caf9'];
const randomColor = () => COLORS[Math.floor(Math.random() * COLORS.length)];
const clients = new Map();
const sendTo = (u, d) => { const c = clients.get(u); if (!c) return; const p = JSON.stringify(d); for (const w of c) if (w.readyState === WebSocket.OPEN) w.send(p); };
const broadcast = (d) => { const p = JSON.stringify(d); for (const [,c] of clients) for (const w of c) if (w.readyState === WebSocket.OPEN) w.send(p); };

wss.on('connection', (ws) => {
  let me = null;
  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    if (msg.type === 'auth') {
      try {
        const pl = jwt.verify(msg.token, JWT_SECRET); me = pl.username;
        if (!clients.has(me)) clients.set(me, new Set());
        clients.get(me).add(ws);
        const db = loadDB();
        if (db.users[me]) { db.users[me].online = true; db.users[me].last_seen = Date.now(); saveDB(db); }
        broadcast({ type: 'presence', username: me, online: true });
        ws.send(JSON.stringify({ type: 'auth_ok' }));
      } catch { ws.send(JSON.stringify({ type: 'auth_err' })); }
      return;
    }
    if (!me) return;
    if (msg.type === 'message') {
      const to = (msg.to||'').toLowerCase(), text = (msg.text||'').trim().slice(0,2000);
      if (!to || !text) return;
      const db = loadDB(); if (!db.users[to]) return;
      const id = uuidv4(), ck = convKey(me, to), ts = Date.now();
      if (!db.messages[ck]) db.messages[ck] = [];
      db.messages[ck].push({ id, from: me, to, text, ts, edited: false, deleted: false, read_at: 0 });
      saveDB(db);
      const pkt = { type: 'message', id, from: me, to, text, ts, edited: false };
      sendTo(me, pkt); sendTo(to, pkt);
    }
    if (msg.type === 'read') {
      const db = loadDB(), ck = convKey(me, msg.partner||'');
      if (db.messages[ck]) { db.messages[ck].forEach(m => { if (m.to === me && !m.read_at) m.read_at = Date.now(); }); saveDB(db); }
      sendTo(msg.partner, { type: 'read', by: me });
    }
    if (msg.type === 'typing') sendTo(msg.to, { type: 'typing', from: me, active: !!msg.active });
    if (msg.type === 'edit') {
      const db = loadDB();
      for (const ck of Object.keys(db.messages)) {
        const m = db.messages[ck].find(m => m.id === msg.id && m.from === me);
        if (m) { m.text = (msg.text||'').trim(); m.edited = true; saveDB(db); sendTo(m.from, { type:'edit', id:msg.id, text:m.text }); sendTo(m.to, { type:'edit', id:msg.id, text:m.text }); break; }
      }
    }
    if (msg.type === 'delete') {
      const db = loadDB();
      for (const ck of Object.keys(db.messages)) {
        const m = db.messages[ck].find(m => m.id === msg.id && m.from === me);
        if (m) { m.deleted = true; m.text = ''; saveDB(db); sendTo(m.from, { type:'delete', id:msg.id }); sendTo(m.to, { type:'delete', id:msg.id }); break; }
      }
    }
  });
  ws.on('close', () => {
    if (!me) return;
    const c = clients.get(me); if (c) { c.delete(ws); if (c.size === 0) clients.delete(me); }
    if (!clients.has(me)) {
      const db = loadDB(); if (db.users[me]) { db.users[me].online = false; db.users[me].last_seen = Date.now(); saveDB(db); }
      broadcast({ type: 'presence', username: me, online: false, last_seen: Date.now() });
    }
  });
});

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const verifyToken = (req) => { const t = (req.headers.authorization||'').replace('Bearer ',''); if (!t) return null; try { return jwt.verify(t, JWT_SECRET); } catch { return null; } };

app.post('/api/register', (req, res) => {
  const { username, nickname, password } = req.body||{};
  const u = (username||'').toLowerCase().trim();
  if (!/^[a-zA-Z0-9]{4,20}$/.test(u)) return res.status(400).json({ error: 'Username: 4-20 символов, только латиница и цифры' });
  if (!nickname||nickname.length>30) return res.status(400).json({ error: 'Никнейм: 1-30 символов' });
  if (!password||password.length<4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  const db = loadDB(); if (db.users[u]) return res.status(409).json({ error: 'Username уже занят' });
  db.users[u] = { id: uuidv4(), username: u, nickname, password_hash: bcrypt.hashSync(password, 10), avatar_color: randomColor(), bio: '', online: false, last_seen: 0, created_at: Date.now() };
  saveDB(db);
  const token = jwt.sign({ username: u }, JWT_SECRET, { expiresIn: '30d' });
  const { password_hash, ...safe } = db.users[u];
  res.json({ token, user: safe });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body||{};
  const u = (username||'').toLowerCase().trim();
  const db = loadDB(), user = db.users[u];
  if (!user||!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Неверный username или пароль' });
  const token = jwt.sign({ username: u }, JWT_SECRET, { expiresIn: '30d' });
  const { password_hash, ...safe } = user;
  res.json({ token, user: safe });
});

app.get('/api/me', (req, res) => {
  const p = verifyToken(req); if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const db = loadDB(), user = db.users[p.username]; if (!user) return res.status(404).json({ error: 'Not found' });
  const { password_hash, ...safe } = user; res.json(safe);
});

app.patch('/api/me', (req, res) => {
  const p = verifyToken(req); if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const { nickname, bio, avatar_color, old_password, new_password } = req.body||{};
  const db = loadDB(), user = db.users[p.username]; if (!user) return res.status(404).json({ error: 'Not found' });
  if (nickname) user.nickname = nickname.trim().slice(0,30);
  if (bio !== undefined) user.bio = bio.slice(0,150);
  if (avatar_color) user.avatar_color = avatar_color;
  if (old_password && new_password) {
    if (!bcrypt.compareSync(old_password, user.password_hash)) return res.status(400).json({ error: 'Старый пароль неверный' });
    if (new_password.length < 4) return res.status(400).json({ error: 'Новый пароль минимум 4 символа' });
    user.password_hash = bcrypt.hashSync(new_password, 10);
  }
  saveDB(db); const { password_hash, ...safe } = user; res.json(safe);
});

app.get('/api/users/search', (req, res) => {
  const p = verifyToken(req); if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const q = (req.query.q||'').toLowerCase().trim(); if (!q) return res.json([]);
  const db = loadDB();
  const results = Object.values(db.users).filter(u => u.username !== p.username && u.username.startsWith(q)).slice(0,10).map(({ password_hash, ...s }) => s);
  res.json(results);
});

app.get('/api/users/:username', (req, res) => {
  const p = verifyToken(req); if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const db = loadDB(), user = db.users[req.params.username.toLowerCase()]; if (!user) return res.status(404).json({ error: 'Не найден' });
  const { password_hash, ...safe } = user; res.json(safe);
});

app.get('/api/messages/:partner', (req, res) => {
  const p = verifyToken(req); if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const db = loadDB(), ck = convKey(p.username, req.params.partner.toLowerCase());
  res.json((db.messages[ck]||[]).slice(-50));
});

app.get('/api/conversations', (req, res) => {
  const p = verifyToken(req); if (!p) return res.status(401).json({ error: 'Unauthorized' });
  const db = loadDB(), result = [];
  for (const [ck, msgs] of Object.entries(db.messages)) {
    if (!msgs.length) continue;
    const [a, b] = ck.split('__'), other = a === p.username ? b : b === p.username ? a : null;
    if (!other || !db.users[other]) continue;
    const last = msgs[msgs.length-1], unread = msgs.filter(m => m.to === p.username && !m.read_at).length;
    const { password_hash, ...ps } = db.users[other];
    result.push({ conv_key: ck, from_user: last.from, to_user: last.to, text: last.text, deleted: last.deleted, created_at: last.ts, unread, partner: ps });
  }
  result.sort((a,b) => b.created_at - a.created_at);
  res.json(result);
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
server.listen(PORT, () => console.log(`✅ Vibe запущен на http://localhost:${PORT}`));
