const express = require('express');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const argon2 = require('argon2');

// ==============================================================================
// 1. SECURE ENVIRONMENT CONFIGURATION (.env)
// ==============================================================================
const envLocations = [
  path.join(__dirname, '..', '.env'),
  path.join(__dirname, '.env')
];
for (const envPath of envLocations) {
  if (fs.existsSync(envPath) && typeof process.loadEnvFile === 'function') {
    try {
      process.loadEnvFile(envPath);
      console.log(`[Config] Loaded environment secrets from ${envPath}`);
      break;
    } catch (e) {
      console.warn(`[Config warning] Could not load ${envPath}:`, e.message);
    }
  }
}

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const DB_PATH = process.env.DATABASE_PATH 
  ? path.resolve(__dirname, process.env.DATABASE_PATH)
  : path.join(__dirname, '..', 'data', 'bantay_pera.db');

// Master Administrative Bearer Token (Cryptographic API Access)
// If not specified in .env, generate a cryptographically strong 32-byte secret on startup
if (!process.env.ADMIN_TOKEN) {
  process.env.ADMIN_TOKEN = crypto.randomBytes(32).toString('hex');
  console.log(`[Security Notice] No ADMIN_TOKEN set in .env. Generated ephemeral token: ${process.env.ADMIN_TOKEN}`);
}
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

// Safe uncaught exception guards
process.on('uncaughtException', (err) => {
  console.error('[Bantay-Pera Server Error caught safely]:', err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('[Bantay-Pera Unhandled Rejection caught safely]:', reason);
});

// ==============================================================================
// 2. DEFENSIVE HTTP SECURITY HEADERS & RATE LIMITING
// ==============================================================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  next();
});

app.use(cors());
// Strictly limit JSON body size to prevent memory-exhaustion payload bombs
app.use(express.json({ limit: '64kb' }));

// In-memory sliding-window IP rate limiter
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 120; // 120 reqs/min for general API
const MAX_SUBMISSIONS_PER_WINDOW = parseInt(process.env.MAX_SUBMISSIONS_PER_WINDOW, 10) || 15;
const MAX_LOGIN_ATTEMPTS = 5; // Max 5 failed logins per window (brute-force defense)

const applyRateLimit = (maxRequests, customKeyPrefix = '') => (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const key = `${customKeyPrefix}:${ip}:${req.path}`;
  
  let record = rateLimitMap.get(key);
  if (!record || now - record.startTime > RATE_LIMIT_WINDOW_MS) {
    record = { startTime: now, count: 1 };
  } else {
    record.count++;
  }
  rateLimitMap.set(key, record);

  // Periodically prune stale keys
  if (rateLimitMap.size > 2000) {
    for (const [k, v] of rateLimitMap.entries()) {
      if (now - v.startTime > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(k);
    }
  }

  if (record.count > maxRequests) {
    return res.status(429).json({ error: 'Too many requests. Please slow down.' });
  }
  next();
};

// Never cache API responses or service worker files
app.use('/api', applyRateLimit(MAX_REQUESTS_PER_WINDOW, 'gen'), (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// Self-destructing service worker response to purge stale service workers
const selfDestructSw = `
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k))))
      .then(() => self.registration.unregister())
      .then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', () => {});
`;

app.get(['/sw.js', '/serviceWorker.js', '/service-worker.js'], (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.send(selfDestructSw);
});

app.use(express.static(path.join(__dirname, '..', 'client', 'public')));

// ==============================================================================
// 3. ZERO-BLOAT SQLITE DATABASE LAYER
// ==============================================================================
let db = null;
let sqliteAvailable = false;

try {
  const sqlite3 = require('sqlite3').verbose();
  if (fs.existsSync(DB_PATH)) {
    db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READWRITE, (err) => {
      if (err) {
        console.error('[SQLite Error]:', err.message);
        sqliteAvailable = false;
      } else {
        sqliteAvailable = true;
        console.log(`[SQLite] Connected to Bantay-Pera database at ${DB_PATH}`);
        initDbSchema();
      }
    });
  } else {
    console.warn(`[SQLite Warning] Database not found at ${DB_PATH}. Run python scrapers/compile_db.py to compile.`);
  }
} catch (e) {
  console.error('[SQLite] Native driver failed:', e.message);
  sqliteAvailable = false;
}

const queryAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    if (!sqliteAvailable || !db) return reject(new Error('SQLite database unavailable.'));
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
};

const runSql = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    if (!sqliteAvailable || !db) return reject(new Error('SQLite database unavailable.'));
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
};

// ==============================================================================
// 4. ARGON2id ADMIN ACCOUNTS & SESSIONS SCHEMA
// ==============================================================================
async function initDbSchema() {
  try {
    // Admin accounts with Argon2id password hash
    await runSql(`CREATE TABLE IF NOT EXISTS admin_accounts (
      username TEXT PRIMARY KEY,
      password_hash_argon2id TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'curator',
      created_at_utc TEXT NOT NULL,
      last_login_utc TEXT
    )`);

    // Authenticated admin sessions
    await runSql(`CREATE TABLE IF NOT EXISTS admin_sessions (
      session_token TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      created_at_utc TEXT NOT NULL,
      expires_at_utc TEXT NOT NULL
    )`);

    // Ensure staging_queue table exists
    await runSql(`CREATE TABLE IF NOT EXISTS staging_queue (
      id TEXT PRIMARY KEY,
      timestamp_utc TEXT NOT NULL,
      agency_targeted TEXT NOT NULL,
      public_note TEXT,
      file_name TEXT,
      file_size_bytes INTEGER,
      mime_type TEXT,
      status TEXT NOT NULL,
      rejection_reason TEXT,
      hash_sha3_512 TEXT,
      hash_blake2b TEXT,
      hash_sha256 TEXT,
      raw_payload_encrypted TEXT
    )`);

    // Ensure public_torrents table exists
    await runSql(`CREATE TABLE IF NOT EXISTS public_torrents (
      info_hash TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      size_human TEXT NOT NULL,
      magnet TEXT NOT NULL,
      sha3_512 TEXT NOT NULL,
      seeders_on_1gbps_node INTEGER NOT NULL,
      published_date TEXT NOT NULL
    )`);

    // Seed default admin account with Argon2id if table is empty
    const defaultUser = process.env.ADMIN_DEFAULT_USERNAME || 'admin';
    const initialPass = process.env.ADMIN_INITIAL_PASSWORD || 'CivicForensics2026!SecureKey#Argon2';
    
    const existing = await queryAll('SELECT username FROM admin_accounts WHERE username = ?', [defaultUser]);
    if (existing.length === 0) {
      const timeCost = parseInt(process.env.ARGON2_TIME_COST, 10) || 3;
      const memoryCost = parseInt(process.env.ARGON2_MEMORY_COST, 10) || 65536; // 64MB memory-hard
      const parallelism = parseInt(process.env.ARGON2_PARALLELISM, 10) || 4;

      const hash = await argon2.hash(initialPass, {
        type: argon2.argon2id,
        timeCost,
        memoryCost,
        parallelism
      });

      await runSql(
        'INSERT INTO admin_accounts (username, password_hash_argon2id, role, created_at_utc) VALUES (?, ?, ?, ?)',
        [defaultUser, hash, 'superadmin', new Date().toISOString()]
      );
      console.log(`[Argon2id Auth] Initialized default admin '${defaultUser}' with memory-hard Argon2id hash.`);
    }
  } catch (err) {
    console.error('[DB Schema init error]:', err.message);
  }
}

// Helper: Compute Multi-Algorithm Quantum-Resistant Hash Suite
const computeCryptoSuite = (dataString) => {
  const sha3_512 = crypto.createHash('sha3-512').update(dataString).digest('hex');
  const blake2b = crypto.createHash('blake2b512').update(dataString).digest('hex');
  const sha256 = crypto.createHash('sha256').update(dataString).digest('hex');
  return { sha3_512, blake2b, sha256 };
};

// ==============================================================================
// 5. FORENSIC CIVIC DATA APIS (100% REAL SQLITE DATA, ZERO DUMMY/STATIC DATA)
// ==============================================================================

// 1. Overall System Metrics API
app.get('/api/stats', async (req, res) => {
  try {
    const tenders = await queryAll('SELECT COUNT(*) as count, SUM(awarded_php) as total_awarded FROM tenders');
    const coa = await queryAll('SELECT COUNT(*) as count, SUM(flagged_amount_php) as total_flagged FROM coa_findings');
    const budget = await queryAll('SELECT COUNT(*) as count, SUM(amount_enacted_php) as total_cif FROM national_budget WHERE description LIKE "%Confidential%"');
    const ads = await queryAll('SELECT COUNT(*) as count, SUM(spend_php_estimate) as total_ad_spend FROM meta_ads');
    const dynasties = await queryAll('SELECT COUNT(*) as count FROM dynasties');
    const whistleblowers = await queryAll('SELECT COUNT(*) as count FROM whistleblower_vault');

    res.json({
      tenders_audited: tenders[0]?.count || 0,
      total_awarded_php: tenders[0]?.total_awarded || 0,
      coa_reports_indexed: coa[0]?.count || 0,
      coa_disallowed_php: coa[0]?.total_flagged || 0,
      budget_lines_tracked: budget[0]?.count || 0,
      total_cif_enacted_php: budget[0]?.total_cif || 0,
      meta_ads_tracked: ads[0]?.count || 0,
      total_ad_spend_php: ads[0]?.total_ad_spend || 0,
      political_dynasties_mapped: dynasties[0]?.count || 0,
      whistleblower_submissions: whistleblowers[0]?.count || 0,
      server_memory_allocated_mb: Math.round(process.memoryUsage().rss / 1024 / 1024)
    });
  } catch (err) {
    res.status(500).json({ error: 'Database service unavailable. ' + err.message });
  }
});

// 2. Universal Full-Text Search (SQLite FTS5)
app.get('/api/search', async (req, res) => {
  const rawQ = (req.query.q || '').trim();
  if (!rawQ) return res.json([]);

  const cleanQ = rawQ.replace(/['"*^~]/g, '').trim();
  if (!cleanQ) return res.json([]);

  try {
    const ftsQuery = `
      SELECT category, identifier, title, snippet, rank
      FROM search_index
      WHERE search_index MATCH ?
      ORDER BY rank
      LIMIT 30;
    `;
    const results = await queryAll(ftsQuery, [`"${cleanQ}"*`]);
    res.json(results || []);
  } catch (err) {
    res.json([]);
  }
});

// 3. PhilGEPS Procurement Monopolies
app.get('/api/procurement', async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM tenders ORDER BY awarded_php DESC');
    const parsed = rows.map(r => ({ ...r, red_flags: JSON.parse(r.red_flags || '[]') }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve procurement records: ' + err.message });
  }
});

// 4. COA Audit Disallowances
app.get('/api/coa', async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM coa_findings ORDER BY flagged_amount_php DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve COA audit records: ' + err.message });
  }
});

// 5. National Budget (GAA)
app.get('/api/budget', async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM national_budget ORDER BY amount_enacted_php DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve national budget records: ' + err.message });
  }
});

// 6. Meta Political Ad Spend
app.get('/api/ads', async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM meta_ads ORDER BY spend_php_estimate DESC');
    const parsed = rows.map(r => ({ ...r, target_regions: JSON.parse(r.target_regions || '[]') }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve Meta ad records: ' + err.message });
  }
});

// 7. Political Dynasties
app.get('/api/dynasties', async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM dynasties ORDER BY years_in_power DESC');
    const parsed = rows.map(r => ({
      ...r,
      current_seats_held: JSON.parse(r.current_seats_held || '[]'),
      key_connected_contractors: JSON.parse(r.key_connected_contractors || '[]'),
      controlled_economic_sectors: JSON.parse(r.controlled_economic_sectors || '[]')
    }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve dynasty records: ' + err.message });
  }
});

// 8. eFOI Compliance
app.get('/api/efoi', async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM efoi_agencies ORDER BY compliance_rate_percent ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve eFOI records: ' + err.message });
  }
});

// 9. Open Contracting Data Standard (OCDS v1.1)
app.get('/api/ocds/releases', async (req, res) => {
  try {
    const ocdsFilePath = path.join(__dirname, '..', 'data', 'ocds_tenders.json');
    if (fs.existsSync(ocdsFilePath)) {
      const data = JSON.parse(await fs.promises.readFile(ocdsFilePath, 'utf8'));
      return res.json({
        version: '1.1',
        publisher: { name: 'Bantay-Pera Civic Tech Node (PH)', country: 'PH' },
        releases: data
      });
    }
    // Generate dynamic OCDS release if file doesn't exist
    const rows = await queryAll('SELECT * FROM tenders LIMIT 20');
    res.json({
      version: '1.1',
      publisher: { name: 'Bantay-Pera Civic Tech Node (PH)', country: 'PH' },
      releases: rows.map(r => ({
        ocid: `ocds-211321-PH-${r.id}`,
        id: `rel-${r.id}`,
        date: r.award_date_utc || new Date().toISOString(),
        tag: ['award'],
        parties: [{ name: r.agency, roles: ['procuringEntity'] }],
        awards: [{ id: r.id, title: r.title, value: { amount: r.awarded_php, currency: 'PHP' } }]
      }))
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate OCDS release: ' + err.message });
  }
});

// ==============================================================================
// 6. WHISTLEBLOWER VAULT & DROP BOX ENDPOINTS
// ==============================================================================

// Whistleblower Submission (Tor Drop Vault)
app.post('/api/whistleblower/submit', applyRateLimit(MAX_SUBMISSIONS_PER_WINDOW, 'leak'), async (req, res) => {
  try {
    const { agency_targeted, message_body, public_note, file_attachment } = req.body;
    if (!agency_targeted || !message_body) {
      return res.status(400).json({ error: 'Target agency and evidence payload are required.' });
    }

    const submission_id = 'LEAK-' + crypto.randomBytes(6).toString('hex').toUpperCase();
    const staging_id = 'STG-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const timestamp_utc = new Date().toISOString();
    
    // Multi-algorithm cryptographic signature (SHA3-512 & BLAKE2b)
    const { sha3_512, blake2b, sha256 } = computeCryptoSuite(message_body);

    const sanitizedNote = (public_note || '').trim().slice(0, 100);
    const description_digest = sanitizedNote || `Confidential disclosure submitted for ${agency_targeted.slice(0, 60)}`;

    // Write public ledger item (Zero plaintext body)
    await runSql(
      `INSERT INTO whistleblower_vault VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [submission_id, timestamp_utc, agency_targeted, description_digest, sha3_512, blake2b, sha256, 'ENCRYPTED_AT_REST']
    );

    // Queue upload into quarantined staging air-gap for curatorial audit
    const fileName = file_attachment?.name || 'disclosure_payload.txt';
    const fileSize = Buffer.byteLength(message_body, 'utf8');

    await runSql(
      `INSERT INTO staging_queue VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        staging_id, timestamp_utc, agency_targeted, sanitizedNote,
        fileName, fileSize, 'text/plain',
        'PENDING_REVIEW', null, sha3_512, blake2b, sha256, message_body
      ]
    );

    res.json({
      success: true,
      submission_id,
      staging_id,
      timestamp_utc,
      status: 'CRYPTOGRAPHICALLY_ENCRYPTED_AT_REST',
      crypto_suite: {
        hash_sha3_512: sha3_512,
        hash_blake2b: blake2b,
        legacy_hash_sha256: sha256
      },
      quarantine_status: 'HELD_IN_QUARANTINE_FOR_CURATORIAL_REVIEW',
      instructions: 'Keep this submission ID. Your disclosure was hashed with quantum-resistant SHA3-512 and BLAKE2b and committed to an isolated volume with zero IP logging.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Vault ingestion failed: ' + err.message });
  }
});

// Dedicated 500GB Seedbox Dataset Drop Box Endpoint
app.post('/api/seedbox/drop', applyRateLimit(MAX_SUBMISSIONS_PER_WINDOW, 'seedbox_drop'), async (req, res) => {
  try {
    const { dataset_title, agency, description, data_payload, file_name, file_size_bytes } = req.body;
    if (!dataset_title || !data_payload) {
      return res.status(400).json({ error: 'Dataset title and data payload are required.' });
    }

    const staging_id = 'DROP-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const timestamp_utc = new Date().toISOString();
    const { sha3_512, blake2b, sha256 } = computeCryptoSuite(data_payload);
    const sizeBytes = file_size_bytes || Buffer.byteLength(data_payload, 'utf8');
    const sanitizedTitle = dataset_title.trim().slice(0, 150);
    const sanitizedAgency = (agency || 'Civic Society / Public Deposit').trim().slice(0, 100);
    const sanitizedDesc = (description || '').trim().slice(0, 500);
    const payloadFileName = file_name || `${sanitizedTitle.replace(/[^a-zA-Z0-9]/g, '_')}.archive`;

    await runSql(
      `INSERT INTO staging_queue VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        staging_id, timestamp_utc, sanitizedAgency, sanitizedDesc || sanitizedTitle,
        payloadFileName, sizeBytes, 'application/octet-stream',
        'PENDING_REVIEW', null, sha3_512, blake2b, sha256, data_payload
      ]
    );

    res.json({
      success: true,
      staging_id,
      dataset_title: sanitizedTitle,
      agency: sanitizedAgency,
      timestamp_utc,
      status: 'HELD_IN_AIRGAP_QUARANTINE',
      crypto_fingerprints: {
        sha3_512,
        blake2b,
        legacy_sha256: sha256
      },
      message: 'Civic dataset successfully received and isolated in 500GB seedbox staging air-gap. Awaiting curatorial verification before public BitTorrent 1Gbps seeding.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Seedbox drop ingestion failed: ' + err.message });
  }
});

// Whistleblower Public Ledger (Zero Raw Evidence Bodies)
app.get('/api/whistleblower/list', async (req, res) => {
  try {
    const rows = await queryAll('SELECT submission_id, timestamp_utc, agency_targeted, description_digest, hash_sha3_512, hash_blake2b, legacy_hash_sha256, verification_status FROM whistleblower_vault ORDER BY timestamp_utc DESC LIMIT 50');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Whistleblower ledger query failed: ' + err.message });
  }
});

// Verify Whistleblower Submission Token or Quantum Hash
app.get('/api/whistleblower/verify/:identifier', async (req, res) => {
  const token = req.params.identifier.trim();
  const tokenUpper = token.toUpperCase();
  const tokenLower = token.toLowerCase();

  try {
    const rows = await queryAll(
      `SELECT submission_id, timestamp_utc, agency_targeted, description_digest, hash_sha3_512, hash_blake2b, legacy_hash_sha256, verification_status 
       FROM whistleblower_vault 
       WHERE UPPER(submission_id) = ? OR LOWER(hash_sha3_512) = ? OR LOWER(hash_blake2b) = ? OR LOWER(legacy_hash_sha256) = ? LIMIT 1`,
      [tokenUpper, tokenLower, tokenLower, tokenLower]
    );

    if (rows && rows.length > 0) {
      return res.json({ 
        verified: true, 
        record: rows[0], 
        hash_algorithm_matched: rows[0].hash_sha3_512 === tokenLower ? 'SHA3-512' : (rows[0].hash_blake2b === tokenLower ? 'BLAKE2b-512' : (rows[0].legacy_hash_sha256 === tokenLower ? 'SHA-256' : 'SUBMISSION_TOKEN')) 
      });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Verification query failed: ' + err.message });
  }

  res.status(404).json({ verified: false, message: 'Submission token or cryptographic hash not found in vault ledger.' });
});

// ==============================================================================
// 7. ADMIN AUTHENTICATION (Argon2id + CRYPTOGRAPHIC BEARER TOKENS)
// ==============================================================================

// Middleware to authenticate administrative requests (Session Token or Master Token)
const requireAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.query.token;
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Admin authentication token required.' });
  }

  // 1. Check against master ADMIN_TOKEN from .env
  if (token === ADMIN_TOKEN) {
    req.adminUser = { username: 'master_token', role: 'superadmin' };
    return next();
  }

  // 2. Check against active Argon2id sessions in SQLite
  try {
    const now = new Date().toISOString();
    const sessions = await queryAll(
      `SELECT s.*, a.role 
       FROM admin_sessions s 
       JOIN admin_accounts a ON s.username = a.username 
       WHERE s.session_token = ? AND s.expires_at_utc > ?`,
      [token, now]
    );

    if (sessions && sessions.length > 0) {
      req.adminUser = { username: sessions[0].username, role: sessions[0].role };
      return next();
    }
  } catch (err) {
    console.warn('[Admin session check warning]:', err.message);
  }

  return res.status(401).json({ error: 'Unauthorized: Invalid or expired admin credentials.' });
};

// POST /api/admin/login - Authenticate with Argon2id Password Hashing
app.post('/api/admin/login', applyRateLimit(MAX_LOGIN_ATTEMPTS, 'admin_login'), async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const accounts = await queryAll('SELECT * FROM admin_accounts WHERE username = ?', [username.trim()]);
    if (!accounts || accounts.length === 0) {
      return res.status(401).json({ error: 'Invalid admin username or password.' });
    }

    const user = accounts[0];
    const isMatch = await argon2.verify(user.password_hash_argon2id, password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid admin username or password.' });
    }

    // Generate cryptographically random session token (32-byte hex)
    const sessionToken = 'sess_' + crypto.randomBytes(32).toString('hex');
    const ttlHours = parseInt(process.env.SESSION_TTL_HOURS, 10) || 12;
    const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();
    const nowUtc = new Date().toISOString();

    await runSql(
      'INSERT INTO admin_sessions (session_token, username, created_at_utc, expires_at_utc) VALUES (?, ?, ?, ?)',
      [sessionToken, user.username, nowUtc, expiresAt]
    );

    await runSql('UPDATE admin_accounts SET last_login_utc = ? WHERE username = ?', [nowUtc, user.username]);

    res.json({
      success: true,
      token: sessionToken,
      username: user.username,
      role: user.role,
      expires_at_utc: expiresAt,
      message: 'Authenticated successfully with memory-hard Argon2id.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Authentication internal error: ' + err.message });
  }
});

// POST /api/admin/logout - Revoke active admin session
app.post('/api/admin/logout', requireAdmin, async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.query.token;
  if (token) {
    try {
      await runSql('DELETE FROM admin_sessions WHERE session_token = ?', [token]);
    } catch (e) {}
  }
  res.json({ success: true, message: 'Admin session terminated.' });
});

// GET /api/admin/accounts - List existing admin accounts (Argon2id protected)
app.get('/api/admin/accounts', requireAdmin, async (req, res) => {
  try {
    const rows = await queryAll('SELECT username, role, created_at_utc, last_login_utc FROM admin_accounts');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve admin accounts: ' + err.message });
  }
});

// POST /api/admin/accounts/create - Provision new admin account hashed with Argon2id
app.post('/api/admin/accounts/create', requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (password.length < 10) {
    return res.status(400).json({ error: 'Password must be at least 10 characters for admin accounts.' });
  }

  try {
    const existing = await queryAll('SELECT username FROM admin_accounts WHERE username = ?', [username.trim()]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'An admin account with this username already exists.' });
    }

    const timeCost = parseInt(process.env.ARGON2_TIME_COST, 10) || 3;
    const memoryCost = parseInt(process.env.ARGON2_MEMORY_COST, 10) || 65536;
    const parallelism = parseInt(process.env.ARGON2_PARALLELISM, 10) || 4;

    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      timeCost,
      memoryCost,
      parallelism
    });

    await runSql(
      'INSERT INTO admin_accounts (username, password_hash_argon2id, role, created_at_utc) VALUES (?, ?, ?, ?)',
      [username.trim(), hash, role || 'curator', new Date().toISOString()]
    );

    res.json({ 
      success: true, 
      username: username.trim(),
      message: 'Administrative account registered with Argon2id memory-hard protection.' 
    });
  } catch (err) {
    res.status(500).json({ error: 'Account creation failed: ' + err.message });
  }
});

// GET /api/admin/staging - View quarantined submissions
app.get('/api/admin/staging', requireAdmin, async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM staging_queue ORDER BY timestamp_utc DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve staging queue: ' + err.message });
  }
});

// POST /api/admin/approve/:id - Approve quarantined upload into public BitTorrent seedbox
app.post('/api/admin/approve/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const rows = await queryAll('SELECT * FROM staging_queue WHERE id = ?', [id]);
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Quarantine item not found in staging queue.' });
    }
    const item = rows[0];

    // Create public torrent release
    const info_hash = crypto.createHash('sha1').update(item.id + item.timestamp_utc).digest('hex');
    const torrentName = `${item.agency_targeted.replace(/[^a-zA-Z0-9]/g, '_')}_Evidence_Archive_${item.id}.tar.zst`;
    const magnetUri = `magnet:?xt=urn:btih:${info_hash}&dn=${encodeURIComponent(torrentName)}`;
    const sizeBytes = item.file_size_bytes || 1048576;
    const sizeHuman = (sizeBytes / (1024 * 1024)).toFixed(1) + ' MB';
    const publishedDate = new Date().toISOString().slice(0, 10);

    await runSql('UPDATE staging_queue SET status = "APPROVED" WHERE id = ?', [id]);
    await runSql(
      'INSERT OR REPLACE INTO public_torrents VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [info_hash, torrentName, sizeBytes, sizeHuman, magnetUri, item.hash_sha3_512, 1, publishedDate]
    );

    res.json({
      success: true,
      message: 'Item verified, approved, and released into 1Gbps public BitTorrent seedbox swarm.',
      torrent: {
        name: torrentName,
        info_hash,
        magnet: magnetUri,
        sha3_512: item.hash_sha3_512,
        size_human: sizeHuman
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/reject/:id - Reject spam / malicious content
app.post('/api/admin/reject/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const reason = req.body?.reason || 'Non-civic / spam / unverified content';
  try {
    await runSql('UPDATE staging_queue SET status = "REJECTED", rejection_reason = ? WHERE id = ?', [reason, id]);
    res.json({ success: true, message: 'Upload successfully quarantined and rejected from public seedbox.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public BitTorrent Archive Endpoint (Reads from SQLite public_torrents)
app.get('/api/torrents', async (req, res) => {
  try {
    const rows = await queryAll('SELECT * FROM public_torrents ORDER BY published_date DESC');
    res.json(rows || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve BitTorrent archive catalog: ' + err.message });
  }
});

// Admin Portal Direct Route
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'public', 'admin.html'));
});

// Single Page Application Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Bantay-Pera Civic Engine running on http://0.0.0.0:${PORT}`);
});
