const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Config — Change these credentials! ──────────────────────────────────────
const ADMIN_USERNAME = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(
  process.env.ADMIN_PASS || 'admin123',
  10
);
// To change password: set env var ADMIN_PASS=yourpassword before running
// Or edit the default value 'admin123' above

const fs = require('fs');

// ─── SQLite Setup ─────────────────────────────────────────────────────────────
// On Railway: store DB in persistent volume (set RAILWAY_VOLUME_MOUNT_PATH in dashboard)
// Locally: falls back to ./data directory
const dataDir = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? process.env.RAILWAY_VOLUME_MOUNT_PATH
  : path.join(__dirname, 'data');

// Ensure data directory exists before opening database
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const DB_PATH = path.join(dataDir, 'visitors.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

// Create table if not exists
db.exec(`
  CREATE TABLE IF NOT EXISTS visitors (
    id          TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    visit_count INTEGER DEFAULT 1,
    user_agent  TEXT,
    referrer    TEXT,
    hostname    TEXT,
    path        TEXT,
    country     TEXT,
    region      TEXT,
    city        TEXT,
    isp         TEXT,
    org         TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ip ON visitors(ip);
  CREATE INDEX IF NOT EXISTS idx_timestamp ON visitors(timestamp DESC);
`);

// Migrate existing JSON data if present
const jsonPath = path.join(dataDir, 'visitors.json');
if (fs.existsSync(jsonPath)) {
  try {
    const existing = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    if (Array.isArray(existing) && existing.length > 0) {
      const insert = db.prepare(`
        INSERT OR IGNORE INTO visitors
          (id, ip, timestamp, last_seen, visit_count, user_agent, referrer, hostname, path,
           country, region, city, isp, org)
        VALUES
          (@id, @ip, @timestamp, @last_seen, @visit_count, @user_agent, @referrer, @hostname, @path,
           @country, @region, @city, @isp, @org)
      `);
      const migrate = db.transaction((rows) => {
        for (const v of rows) {
          insert.run({
            id: v.id,
            ip: v.ip,
            timestamp: v.timestamp,
            last_seen: v.lastSeen || v.timestamp,
            visit_count: v.visitCount || 1,
            user_agent: v.userAgent || null,
            referrer: v.referrer || null,
            hostname: v.hostname || null,
            path: v.path || '/',
            country: v.geo?.country || null,
            region: v.geo?.region || null,
            city: v.geo?.city || null,
            isp: v.geo?.isp || null,
            org: v.geo?.org || null,
          });
        }
      });
      migrate(existing);
      console.log(`[MIGRATE] Imported ${existing.length} records from visitors.json → SQLite`);
      // Rename old file so we don't migrate again
      fs.renameSync(jsonPath, jsonPath + '.bak');
    }
  } catch (e) {
    console.warn('[MIGRATE] Could not migrate JSON data:', e.message);
  }
}

// ── Prepared statements ───────────────────────────────────────────────────────
const stmtFindByIP    = db.prepare('SELECT * FROM visitors WHERE ip = ?');
const stmtInsert      = db.prepare(`
  INSERT INTO visitors
    (id, ip, timestamp, last_seen, visit_count, user_agent, referrer, hostname, path,
     country, region, city, isp, org)
  VALUES
    (@id, @ip, @timestamp, @last_seen, @visit_count, @user_agent, @referrer, @hostname, @path,
     @country, @region, @city, @isp, @org)
`);
const stmtUpdateVisit = db.prepare(`
  UPDATE visitors SET visit_count = visit_count + 1, last_seen = ? WHERE ip = ?
`);
const stmtAll         = db.prepare('SELECT * FROM visitors ORDER BY timestamp DESC');
const stmtDeleteAll   = db.prepare('DELETE FROM visitors');
const stmtDeleteOne   = db.prepare('DELETE FROM visitors WHERE id = ?');
const stmtStats       = db.prepare(`
  SELECT
    COUNT(*) as total_unique,
    SUM(visit_count) as total_visits,
    COUNT(DISTINCT country) as total_countries
  FROM visitors
`);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'ip-trap-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }, // 8 hours
}));

const trackLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  res.redirect('/login.html');
}

// ─── Helper: get real IP ──────────────────────────────────────────────────────
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return (
    req.headers['x-real-ip'] ||
    req.headers['cf-connecting-ip'] ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown'
  );
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────
// POST /api/login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (
    username === ADMIN_USERNAME &&
    bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)
  ) {
    req.session.authenticated = true;
    return res.json({ success: true });
  }
  res.status(401).json({ success: false, message: 'Username atau password salah.' });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// GET /api/auth-check
app.get('/api/auth-check', (req, res) => {
  res.json({ authenticated: !!req.session?.authenticated });
});

// ─── Track Route (public) ─────────────────────────────────────────────────────
app.post('/api/track', trackLimiter, async (req, res) => {
  try {
    const ip = getRealIP(req);
    const userAgent = req.headers['user-agent'] || null;
    const referrer  = req.headers['referer'] || req.headers['referrer'] || 'direct';
    const { path: visitPath = '/', hostname = null } = req.body;
    const now = new Date().toISOString();

    // Check if IP already seen → just increment visit count
    const existing = stmtFindByIP.get(ip);
    if (existing) {
      stmtUpdateVisit.run(now, ip);
      return res.json({ success: true, returning: true });
    }

    // Geolocation
    let geo = { country: null, city: null, region: null, isp: null, org: null };
    try {
      const geoRes = await fetch(
        `http://ip-api.com/json/${ip}?fields=country,regionName,city,isp,org,status`
      );
      const geoData = await geoRes.json();
      if (geoData.status === 'success') {
        geo = {
          country: geoData.country || null,
          region:  geoData.regionName || null,
          city:    geoData.city || null,
          isp:     geoData.isp || null,
          org:     geoData.org || null,
        };
      }
    } catch { /* Geo failed — continue */ }

    stmtInsert.run({
      id:          uuidv4(),
      ip,
      timestamp:   now,
      last_seen:   now,
      visit_count: 1,
      user_agent:  userAgent,
      referrer,
      hostname,
      path:        visitPath,
      ...geo,
    });

    console.log(`[TRACKED] ${ip} — ${geo.city || '?'}, ${geo.country || '?'}`);
    res.json({ success: true, returning: false });

  } catch (err) {
    console.error('[TRACK ERROR]', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ─── Admin API Routes (protected) ────────────────────────────────────────────

// GET /api/visitors
app.get('/api/visitors', requireAuth, (req, res) => {
  const visitors = stmtAll.all().map((v) => ({
    id:         v.id,
    ip:         v.ip,
    timestamp:  v.timestamp,
    lastSeen:   v.last_seen,
    visitCount: v.visit_count,
    userAgent:  v.user_agent,
    referrer:   v.referrer,
    hostname:   v.hostname,
    path:       v.path,
    geo: {
      country: v.country,
      region:  v.region,
      city:    v.city,
      isp:     v.isp,
      org:     v.org,
    },
  }));
  const stats = stmtStats.get();
  res.json({
    total:    stats.total_unique,
    visits:   stats.total_visits,
    countries: stats.total_countries,
    visitors,
  });
});

// DELETE /api/visitors — clear all
app.delete('/api/visitors', requireAuth, (req, res) => {
  stmtDeleteAll.run();
  console.log('[ADMIN] All visitor data cleared.');
  res.json({ success: true });
});

// DELETE /api/visitors/:id — delete one
app.delete('/api/visitors/:id', requireAuth, (req, res) => {
  const info = stmtDeleteOne.run(req.params.id);
  if (info.changes === 0)
    return res.status(404).json({ success: false, message: 'Not found.' });
  res.json({ success: true });
});

// Protected admin page — redirect to login if not authed
app.get('/admin.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Catch-all
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 IP Trap Server  →  http://localhost:${PORT}`);
  console.log(`🔐 Admin Login     →  http://localhost:${PORT}/login.html`);
  console.log(`📊 Admin Dashboard →  http://localhost:${PORT}/admin.html`);
  console.log(`💾 Database        →  ${path.join(__dirname, 'data', 'visitors.db')}\n`);
  console.log(`👤 Admin user: "${ADMIN_USERNAME}" / "${process.env.ADMIN_PASS || 'admin123'}"`);
  console.log(`   (set ADMIN_PASS env var to change password)\n`);
});
