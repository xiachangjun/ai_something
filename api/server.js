const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3456;

// 中间件
app.use(express.json());

// ═══ 配置 ═══
const PASSWORD_HASH = crypto.createHash('sha256').update('xiaoyz').digest('hex');
const API_TOKEN = crypto.randomBytes(32).toString('hex');
const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const CLEANUP_INTERVAL = 60000;

console.log('[start] API Token: ' + API_TOKEN);
console.log('[start] password wrong ' + MAX_ATTEMPTS + ' times lock ' + LOCKOUT_MINUTES + ' min');

// ═══ 数据库 ═══
const dbPath = path.join(__dirname, 'birthdays.db');
const db = new Database(dbPath);

db.exec('CREATE TABLE IF NOT EXISTS birthdays (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN (\'solar\', \'lunar\')), date TEXT NOT NULL, lunarYear INTEGER, lunarMonth INTEGER, lunarDay INTEGER, createdAt INTEGER NOT NULL)');
db.exec('CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, attempt_time INTEGER NOT NULL, PRIMARY KEY (ip))');

function isLocked(ip) {
  var row = db.prepare('SELECT attempt_time FROM login_attempts WHERE ip = ?').get(ip);
  if (!row) return false;
  return (Date.now() - row.attempt_time) / 60000 < LOCKOUT_MINUTES;
}

function getAttempts(ip) {
  var recent = Date.now() - LOCKOUT_MINUTES * 60000;
  db.prepare('DELETE FROM login_attempts WHERE attempt_time < ?').run(recent);
  var row = db.prepare('SELECT COUNT(*) as cnt FROM login_attempts WHERE ip = ? AND attempt_time > ?').get(ip, recent);
  return row ? row.cnt : 0;
}

function recordFailedAttempt(ip) {
  db.prepare('INSERT OR REPLACE INTO login_attempts (ip, attempt_time) VALUES (?, ?)').run(ip, Date.now());
  return getAttempts(ip);
}

function clearAttempts(ip) {
  db.prepare('DELETE FROM login_attempts WHERE ip = ?').run(ip);
}

function getClientIP(req) {
  var fwd = req.headers['x-forwarded-for'];
  return (fwd ? fwd.split(',')[0].trim() : null) || req.ip || 'unknown';
}

function authMiddleware(req, res, next) {
  var token = req.headers['x-api-token'];
  if (!token || token !== API_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// 登录
app.post('/api/auth/login', function(req, res) {
  var password = req.body.password;
  var ip = getClientIP(req);

  if (isLocked(ip)) {
    return res.status(429).json({ error: 'locked', message: 'too many attempts, try again later', locked: true });
  }

  if (!password) {
    return res.status(400).json({ error: 'password required' });
  }

  var hash = crypto.createHash('sha256').update(password).digest('hex');
  if (hash === PASSWORD_HASH) {
    clearAttempts(ip);
    return res.json({ success: true, token: API_TOKEN });
  } else {
    var attempts = recordFailedAttempt(ip);
    var remaining = MAX_ATTEMPTS - attempts;
    if (remaining <= 0) {
      return res.status(429).json({ error: 'locked', message: 'too many attempts, try again later', locked: true });
    }
    return res.status(401).json({ error: 'invalid_password', message: 'wrong password, remaining: ' + remaining, remaining: remaining });
  }
});

// 获取所有生日
app.get('/api/birthdays', authMiddleware, function(req, res) {
  var rows = db.prepare('SELECT id, name, type, date, lunarYear, lunarMonth, lunarDay FROM birthdays ORDER BY createdAt ASC').all();
  res.json(rows);
});

// 添加生日
app.post('/api/birthdays', authMiddleware, function(req, res) {
  var name = req.body.name, type = req.body.type, date = req.body.date;
  var lunarYear = req.body.lunarYear, lunarMonth = req.body.lunarMonth, lunarDay = req.body.lunarDay;
  if (!name || !type || !date) {
    return res.status(400).json({ error: 'name, type, date required' });
  }
  var id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  var createdAt = Date.now();
  db.prepare('INSERT INTO birthdays (id, name, type, date, lunarYear, lunarMonth, lunarDay, createdAt) VALUES (?,?,?,?,?,?,?,?)').run(id, name.trim(), type, date, lunarYear || null, lunarMonth || null, lunarDay || null, createdAt);
  var row = db.prepare('SELECT id, name, type, date, lunarYear, lunarMonth, lunarDay FROM birthdays WHERE id = ?').get(id);
  res.status(201).json(row);
});

// 删除
app.delete('/api/birthdays/:id', authMiddleware, function(req, res) {
  var result = db.prepare('DELETE FROM birthdays WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

// seed
app.post('/api/birthdays/seed', authMiddleware, function(req, res) {
  var count = db.prepare('SELECT COUNT(*) as c FROM birthdays').get().c;
  if (count > 0) return res.json({ message: 'already seeded', count: count });
  var seedData = [
    { name: '\u7384\u6850', type: 'solar', date: '1993-07-03' },
    { name: '\u8001\u5a46', type: 'lunar', date: '1993-06-16', lunarYear: 1993, lunarMonth: 6, lunarDay: 16 },
    { name: '\u7f8e\u5176', type: 'lunar', date: '1993-07-07', lunarYear: 1993, lunarMonth: 7, lunarDay: 7 },
    { name: '\u79cb\u96ea', type: 'lunar', date: '1993-09-18', lunarYear: 1993, lunarMonth: 9, lunarDay: 18 },
    { name: '\u7239', type: 'solar', date: '1967-03-15' },
    { name: '\u5988', type: 'lunar', date: '1967-03-01', lunarYear: 1967, lunarMonth: 3, lunarDay: 1 },
    { name: '\u6b23\u6b23', type: 'lunar', date: '1994-03-04', lunarYear: 1994, lunarMonth: 3, lunarDay: 4 },
  ];
  var insert = db.prepare('INSERT INTO birthdays (id, name, type, date, lunarYear, lunarMonth, lunarDay, createdAt) VALUES (?,?,?,?,?,?,?,?)');
  var tx = db.transaction(function(items) {
    for (var i = 0; i < items.length; i++) {
      var item = items[i];
      var id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      insert.run(id, item.name, item.type, item.date, item.lunarYear || null, item.lunarMonth || null, item.lunarDay || null, Date.now());
    }
  });
  tx(seedData);
  var rows = db.prepare('SELECT id, name, type, date, lunarYear, lunarMonth, lunarDay FROM birthdays ORDER BY createdAt ASC').all();
  res.status(201).json({ message: 'seeded', data: rows });
});

// 定期清理
setInterval(function() {
  var cutoff = Date.now() - LOCKOUT_MINUTES * 60000;
  db.prepare('DELETE FROM login_attempts WHERE attempt_time < ?').run(cutoff);
}, CLEANUP_INTERVAL);

// 启动
app.listen(PORT, '127.0.0.1', function() {
  console.log('Birthday API running on http://127.0.0.1:' + PORT);
  console.log('Token: ' + API_TOKEN);
});
