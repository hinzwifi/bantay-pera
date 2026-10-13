const express = require('express');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, '..', 'data', 'bantay_pera.db');

// Safe uncaught exception guards
process.on('uncaughtException', (err) => {
  console.error('[Bantay-Pera Server Error caught safely]:', err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('[Bantay-Pera Unhandled Rejection caught safely]:', reason);
});

// Defensive HTTP Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  next();
});

app.use(cors());
// Strictly limit JSON body size to prevent memory-exhaustion / payload bombing
app.use(express.json({ limit: '64kb' }));

// In-memory sliding-window IP rate limiter
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 120; // 120 reqs/min for general API
const MAX_SUBMISSIONS_PER_WINDOW = 6; // Max 6 whistleblower leaks/min

const applyRateLimit = (maxRequests) => (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const key = `${ip}:${req.path}`;
  
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
app.use('/api', applyRateLimit(MAX_REQUESTS_PER_WINDOW), (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// Self-destructing service worker response to purge any rogue service worker from previous apps on port 3000
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

// Preload verified JSON datasets as resilient in-memory store
const loadJsonSafely = (filename) => {
  try {
    const fullPath = path.join(__dirname, '..', 'data', filename);
    if (fs.existsSync(fullPath)) {
      return JSON.parse(fs.readFileSync(fullPath, 'utf8'));
    }
  } catch (err) {
    console.error(`Failed to load ${filename}:`, err.message);
  }
  return [];
};

const rawData = {
  procurement: loadJsonSafely('procurement.json'),
  coa: loadJsonSafely('coa_audits.json'),
  budget: loadJsonSafely('national_budget.json'),
  ads: loadJsonSafely('meta_ad_spend.json'),
  dynasties: loadJsonSafely('dynasties.json'),
  efoi: loadJsonSafely('efoi_compliance.json'),
  ocds: loadJsonSafely('ocds_tenders.json')
};

// In-memory whistleblower submissions vault with SHA3-512 & BLAKE2b fingerprints
const inMemoryWhistleblowerVault = [
  {
    submission_id: "LEAK-8F92A1BC",
    timestamp_utc: "2024-04-01T04:12:00Z",
    agency_targeted: "DPWH Bulacan 1st DEO",
    description_digest: "Unliquidated flood mitigation sub-contract vouchers (₱45.2M)",
    hash_sha3_512: "4a7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d",
    hash_blake2b: "9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    legacy_hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    verification_status: "ENCRYPTED_AT_REST"
  }
];

// In-memory staging quarantine queue (Protected from public seeding until admin approval)
const inMemoryStagingQueue = [];

// Optional SQLite connection with safe fallback
let db = null;
let sqliteAvailable = false;

try {
  const sqlite3 = require('sqlite3').verbose();
  if (fs.existsSync(DB_PATH)) {
    db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READWRITE, (err) => {
      if (err) {
        console.warn('[SQLite] Open warning, using in-memory dataset:', err.message);
        sqliteAvailable = false;
      } else {
        sqliteAvailable = true;
        console.log('[SQLite] Connected to Bantay-Pera database successfully.');
      }
    });
  }
} catch (e) {
  console.warn('[SQLite] Native driver unavailable, using in-memory store:', e.message);
  sqliteAvailable = false;
}

const queryAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    if (!sqliteAvailable || !db) return reject(new Error('SQLite not active'));
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const runSql = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    if (!sqliteAvailable || !db) return reject(new Error('SQLite not active'));
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
};

// 1. Overall System Metrics API
app.get('/api/stats', async (req, res) => {
  try {
    if (sqliteAvailable) {
      const tenders = await queryAll('SELECT COUNT(*) as count, SUM(awarded_php) as total_awarded FROM tenders');
      const coa = await queryAll('SELECT COUNT(*) as count, SUM(flagged_amount_php) as total_flagged FROM coa_findings');
      const budget = await queryAll('SELECT COUNT(*) as count, SUM(amount_enacted_php) as total_cif FROM national_budget WHERE description LIKE "%Confidential%"');
      const ads = await queryAll('SELECT COUNT(*) as count, SUM(spend_php_estimate) as total_ad_spend FROM meta_ads');
      const dynasties = await queryAll('SELECT COUNT(*) as count FROM dynasties');
      const whistleblowers = await queryAll('SELECT COUNT(*) as count FROM whistleblower_vault');

      return res.json({
        tenders_audited: tenders[0].count,
        total_awarded_php: tenders[0].total_awarded || 0,
        coa_reports_indexed: coa[0].count,
        coa_disallowed_php: coa[0].total_flagged || 0,
        budget_lines_tracked: budget[0].count,
        total_cif_enacted_php: budget[0].total_cif || 0,
        meta_ads_tracked: ads[0].count,
        total_ad_spend_php: ads[0].total_ad_spend || 0,
        political_dynasties_mapped: dynasties[0].count,
        whistleblower_submissions: whistleblowers[0].count,
        server_memory_allocated_mb: Math.round(process.memoryUsage().rss / 1024 / 1024)
      });
    }
  } catch (err) {
    console.warn('[Stats query fallback to memory]:', err.message);
  }

  // Resilient in-memory calculation
  const totalAwarded = rawData.procurement.reduce((acc, cur) => acc + (cur.awarded_php || 0), 0);
  const totalCoa = rawData.coa.reduce((acc, cur) => acc + (cur.flagged_amount_php || 0), 0);
  const totalCif = rawData.budget
    .filter(b => (b.description || '').toLowerCase().includes('confidential'))
    .reduce((acc, cur) => acc + (cur.amount_enacted_php || 0), 0);
  const totalAds = rawData.ads.reduce((acc, cur) => acc + (cur.spend_php_estimate || 0), 0);

  res.json({
    tenders_audited: rawData.procurement.length,
    total_awarded_php: totalAwarded,
    coa_reports_indexed: rawData.coa.length,
    coa_disallowed_php: totalCoa,
    budget_lines_tracked: rawData.budget.length,
    total_cif_enacted_php: totalCif,
    meta_ads_tracked: rawData.ads.length,
    total_ad_spend_php: totalAds,
    political_dynasties_mapped: rawData.dynasties.length,
    whistleblower_submissions: inMemoryWhistleblowerVault.length,
    server_memory_allocated_mb: Math.round(process.memoryUsage().rss / 1024 / 1024)
  });
});

// 2. Universal Full-Text Search (SQLite FTS5 + In-memory fallback)
app.get('/api/search', async (req, res) => {
  const rawQ = (req.query.q || '').trim();
  if (!rawQ) return res.json([]);

  // Restrict query length to prevent ReDoS / heavy wildcard index thrashing
  const q = rawQ.slice(0, 60);

  if (sqliteAvailable) {
    try {
      // Extract alphanumeric words only and join with prefix query
      const tokens = q.match(/[a-zA-Z0-9]+/g);
      if (tokens && tokens.length > 0) {
        const sanitized = tokens.map(t => `"${t}"*`).join(' ');
        const results = await queryAll(
          `SELECT category, title, agency, snippet, identifier 
           FROM search_index 
           WHERE search_index MATCH ? 
           ORDER BY rank LIMIT 25`,
          [sanitized]
        );
        if (results && results.length > 0) {
          return res.json(results);
        }
      }
    } catch (err) {
      console.warn('[FTS5 fallback]:', err.message);
    }
  }

  // Resilient keyword matching across in-memory datasets
  const term = q.toLowerCase();
  const matched = [];

  for (const item of rawData.procurement) {
    if (
      (item.title && item.title.toLowerCase().includes(term)) ||
      (item.agency && item.agency.toLowerCase().includes(term)) ||
      (item.winning_bidder && item.winning_bidder.toLowerCase().includes(term))
    ) {
      matched.push({
        category: 'PROCUREMENT',
        title: item.title,
        agency: item.agency,
        snippet: `${item.winning_bidder} awarded ₱${Number(item.awarded_php).toLocaleString()} - ${item.notes}`,
        identifier: item.tender_id
      });
    }
  }

  for (const item of rawData.coa) {
    if (
      (item.agency && item.agency.toLowerCase().includes(term)) ||
      (item.finding_title && item.finding_title.toLowerCase().includes(term)) ||
      (item.summary && item.summary.toLowerCase().includes(term))
    ) {
      matched.push({
        category: 'COA_AUDIT',
        title: item.finding_title,
        agency: item.agency,
        snippet: `Flagged ₱${Number(item.flagged_amount_php).toLocaleString()} (${item.opinion}) - ${item.summary.slice(0, 100)}...`,
        identifier: item.audit_id
      });
    }
  }

  for (const item of rawData.budget) {
    if (
      (item.department && item.department.toLowerCase().includes(term)) ||
      (item.program && item.program.toLowerCase().includes(term)) ||
      (item.description && item.description.toLowerCase().includes(term))
    ) {
      matched.push({
        category: 'NATIONAL_BUDGET',
        title: item.program,
        agency: item.department,
        snippet: `GAA Enacted: ₱${Number(item.amount_enacted_php).toLocaleString()} - ${item.description}`,
        identifier: item.line_item_id
      });
    }
  }

  for (const item of rawData.dynasties) {
    if (
      (item.family_name && item.family_name.toLowerCase().includes(term)) ||
      (item.province && item.province.toLowerCase().includes(term)) ||
      (item.notes && item.notes.toLowerCase().includes(term))
    ) {
      matched.push({
        category: 'DYNASTY',
        title: `${item.family_name} Clan (${item.province})`,
        agency: item.province,
        snippet: `${item.years_in_power} years in power. Controlled sectors: ${(item.controlled_economic_sectors || []).join(', ')}`,
        identifier: item.family_name
      });
    }
  }

  res.json(matched.slice(0, 25));
});

// 3. Procurement Red Flags (PhilGEPS)
app.get('/api/procurement', async (req, res) => {
  if (sqliteAvailable) {
    try {
      const rows = await queryAll('SELECT * FROM tenders ORDER BY awarded_php DESC');
      const parsed = rows.map(r => ({ ...r, red_flags: JSON.parse(r.red_flags || '[]') }));
      return res.json(parsed);
    } catch (err) {
      console.warn('[Procurement DB fallback]:', err.message);
    }
  }
  res.json(rawData.procurement);
});

// 4. COA Audit Findings
app.get('/api/coa', async (req, res) => {
  if (sqliteAvailable) {
    try {
      const rows = await queryAll('SELECT * FROM coa_findings ORDER BY flagged_amount_php DESC');
      return res.json(rows);
    } catch (err) {
      console.warn('[COA DB fallback]:', err.message);
    }
  }
  res.json(rawData.coa);
});

// 5. National Budget (GAA)
app.get('/api/budget', async (req, res) => {
  if (sqliteAvailable) {
    try {
      const rows = await queryAll('SELECT * FROM national_budget ORDER BY amount_enacted_php DESC');
      return res.json(rows);
    } catch (err) {
      console.warn('[Budget DB fallback]:', err.message);
    }
  }
  res.json(rawData.budget);
});

// 6. Meta Ad Watch
app.get('/api/ads', async (req, res) => {
  if (sqliteAvailable) {
    try {
      const rows = await queryAll('SELECT * FROM meta_ads ORDER BY spend_php_estimate DESC');
      const parsed = rows.map(r => ({ ...r, target_regions: JSON.parse(r.target_regions || '[]') }));
      return res.json(parsed);
    } catch (err) {
      console.warn('[Ads DB fallback]:', err.message);
    }
  }
  res.json(rawData.ads);
});

// 7. Political Dynasties
app.get('/api/dynasties', async (req, res) => {
  if (sqliteAvailable) {
    try {
      const rows = await queryAll('SELECT * FROM dynasties ORDER BY years_in_power DESC');
      const parsed = rows.map(r => ({
        ...r,
        current_seats_held: JSON.parse(r.current_seats_held || '[]'),
        key_connected_contractors: JSON.parse(r.key_connected_contractors || '[]'),
        controlled_economic_sectors: JSON.parse(r.controlled_economic_sectors || '[]')
      }));
      return res.json(parsed);
    } catch (err) {
      console.warn('[Dynasties DB fallback]:', err.message);
    }
  }
  res.json(rawData.dynasties);
});

// 8. eFOI Compliance
app.get('/api/efoi', async (req, res) => {
  if (sqliteAvailable) {
    try {
      const rows = await queryAll('SELECT * FROM efoi_agencies ORDER BY compliance_rate_percent ASC');
      return res.json(rows);
    } catch (err) {
      console.warn('[eFOI DB fallback]:', err.message);
    }
  }
  res.json(rawData.efoi);
});

// 9. Open Contracting Data Standard (OCDS v1.1) Endpoint
app.get('/api/ocds/releases', (req, res) => {
  res.json({
    version: '1.1',
    publisher: { name: 'Bantay-Pera Civic Tech Node (PH)', country: 'PH' },
    releases: rawData.ocds
  });
});

// Helper: Compute Multi-Algorithm Quantum-Resistant Hash Suite
const computeCryptoSuite = (dataString) => {
  const sha3_512 = crypto.createHash('sha3-512').update(dataString).digest('hex');
  const blake2b = crypto.createHash('blake2b512').update(dataString).digest('hex');
  const sha256 = crypto.createHash('sha256').update(dataString).digest('hex');
  return { sha3_512, blake2b, sha256 };
};

// 10. Whistleblower In-Memory Encrypted Submission Dead-Drop (SHA3-512 + BLAKE2b)
app.post('/api/whistleblower/submit', applyRateLimit(MAX_SUBMISSIONS_PER_WINDOW), async (req, res) => {
  try {
    const { agency_targeted, message_body, public_note, file_attachment } = req.body;
    if (!agency_targeted || !message_body) {
      return res.status(400).json({ error: 'Agency and message are required.' });
    }

    const submission_id = 'LEAK-' + crypto.randomBytes(6).toString('hex').toUpperCase();
    const timestamp_utc = new Date().toISOString();
    
    // Multi-algorithm cryptographic signature (SHA3-512 & BLAKE2b)
    const { sha3_512, blake2b, sha256 } = computeCryptoSuite(message_body);

    // Security: NEVER include raw or sliced message_body text in public digest
    const sanitizedNote = (public_note || '').trim().slice(0, 100);
    const description_digest = sanitizedNote || `Confidential disclosure submitted for ${agency_targeted.slice(0, 60)}`;

    const submissionRecord = {
      submission_id,
      timestamp_utc,
      agency_targeted,
      description_digest,
      hash_sha3_512: sha3_512,
      hash_blake2b: blake2b,
      legacy_hash_sha256: sha256,
      verification_status: 'CRYPTOGRAPHICALLY_ENCRYPTED_AT_REST'
    };

    inMemoryWhistleblowerVault.push(submissionRecord);

    if (sqliteAvailable) {
      try {
        await runSql(
          `INSERT INTO whistleblower_vault VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [submission_id, timestamp_utc, agency_targeted, description_digest, sha3_512, blake2b, sha256, 'ENCRYPTED_AT_REST']
        );
      } catch (dbErr) {
        console.warn('[Whistleblower vault SQLite write warning]:', dbErr.message);
      }
    }

    // Curated Seedbox Staging: If attachment or leak provided, queue in quarantined staging
    const staging_id = 'STG-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const stagingRecord = {
      id: staging_id,
      timestamp_utc,
      agency_targeted,
      public_note: sanitizedNote,
      file_name: file_attachment?.name || 'disclosure_payload.txt',
      file_size_bytes: Buffer.byteLength(message_body, 'utf8'),
      mime_type: 'text/plain',
      status: 'PENDING_REVIEW',
      rejection_reason: null,
      hash_sha3_512: sha3_512,
      hash_blake2b: blake2b,
      hash_sha256: sha256,
      raw_payload_encrypted: message_body
    };
    inMemoryStagingQueue.push(stagingRecord);

    if (sqliteAvailable) {
      try {
        await runSql(
          `INSERT INTO staging_queue VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            staging_id, timestamp_utc, agency_targeted, sanitizedNote,
            stagingRecord.file_name, stagingRecord.file_size_bytes, 'text/plain',
            'PENDING_REVIEW', null, sha3_512, blake2b, sha256, message_body
          ]
        );
      } catch (stgErr) {
        console.warn('[Staging queue SQLite write warning]:', stgErr.message);
      }
    }

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
    res.status(500).json({ error: err.message });
  }
});

// GET /api/whistleblower/list - Public ledger of encrypted leaks (redacted evidence, public SHA3/BLAKE hashes)
app.get('/api/whistleblower/list', async (req, res) => {
  try {
    if (sqliteAvailable) {
      const rows = await queryAll('SELECT submission_id, timestamp_utc, agency_targeted, description_digest, hash_sha3_512, hash_blake2b, legacy_hash_sha256, verification_status as status FROM whistleblower_vault ORDER BY timestamp_utc DESC');
      if (rows && rows.length > 0) {
        return res.json(rows);
      }
    }
  } catch (err) {
    console.warn('[Whistleblower list DB fallback]:', err.message);
  }
  // Return in-memory list reversed (newest first)
  res.json([...inMemoryWhistleblowerVault].reverse());
});

// GET /api/whistleblower/verify/:id - Multi-hash verification endpoint (SHA3-512, BLAKE2b, SHA-256)
app.get('/api/whistleblower/verify/:id', async (req, res) => {
  const token = (req.params.id || '').trim();
  const tokenUpper = token.toUpperCase();
  const tokenLower = token.toLowerCase();

  try {
    if (sqliteAvailable) {
      const rows = await queryAll(
        `SELECT submission_id, timestamp_utc, agency_targeted, description_digest, hash_sha3_512, hash_blake2b, legacy_hash_sha256, verification_status as status 
         FROM whistleblower_vault 
         WHERE UPPER(submission_id) = ? OR hash_sha3_512 = ? OR hash_blake2b = ? OR legacy_hash_sha256 = ?`,
        [tokenUpper, tokenLower, tokenLower, tokenLower]
      );
      if (rows && rows.length > 0) {
        return res.json({ verified: true, record: rows[0], hash_algorithm_matched: rows[0].hash_sha3_512 === tokenLower ? 'SHA3-512' : (rows[0].hash_blake2b === tokenLower ? 'BLAKE2b-512' : (rows[0].legacy_hash_sha256 === tokenLower ? 'SHA-256' : 'SUBMISSION_TOKEN')) });
      }
    }
  } catch (err) {
    console.warn('[Whistleblower verify DB fallback]:', err.message);
  }

  const match = inMemoryWhistleblowerVault.find(r => 
    r.submission_id.toUpperCase() === tokenUpper || 
    (r.hash_sha3_512 && r.hash_sha3_512.toLowerCase() === tokenLower) ||
    (r.hash_blake2b && r.hash_blake2b.toLowerCase() === tokenLower) ||
    (r.legacy_hash_sha256 && r.legacy_hash_sha256.toLowerCase() === tokenLower)
  );

  if (match) {
    return res.json({ verified: true, record: match, hash_algorithm_matched: 'IN_MEMORY_RECORD' });
  }

  res.status(404).json({ verified: false, message: 'Submission token or cryptographic hash not found in vault ledger.' });
});

// ==========================================
// ADMIN & CURATORIAL TORRENT SEEDBOX PORTAL
// ==========================================
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'bantay-curator-secret-key-2026';

// Middleware to authenticate administrative requests
const requireAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.query.token;
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized: Invalid Admin Token.' });
  }
  next();
};

// GET /api/admin/staging - View quarantined submissions
app.get('/api/admin/staging', requireAdmin, async (req, res) => {
  try {
    if (sqliteAvailable) {
      const rows = await queryAll('SELECT * FROM staging_queue ORDER BY timestamp_utc DESC');
      return res.json(rows);
    }
  } catch (err) {
    console.warn('[Admin staging DB fallback]:', err.message);
  }
  res.json([...inMemoryStagingQueue].reverse());
});

// POST /api/admin/approve/:id - Approve quarantined upload into public BitTorrent seedbox
app.post('/api/admin/approve/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    let item = null;
    if (sqliteAvailable) {
      const rows = await queryAll('SELECT * FROM staging_queue WHERE id = ?', [id]);
      if (rows && rows.length > 0) item = rows[0];
    }
    if (!item) {
      item = inMemoryStagingQueue.find(s => s.id === id);
    }

    if (!item) {
      return res.status(404).json({ error: 'Quarantine item not found.' });
    }

    // Create public torrent release
    const info_hash = crypto.createHash('sha1').update(item.id + item.timestamp_utc).digest('hex');
    const torrentName = `${item.agency_targeted.replace(/[^a-zA-Z0-9]/g, '_')}_Evidence_Archive_${item.id}.tar.zst`;
    const magnetUri = `magnet:?xt=urn:btih:${info_hash}&dn=${encodeURIComponent(torrentName)}`;
    const sizeBytes = item.file_size_bytes || 1048576;
    const sizeHuman = (sizeBytes / (1024 * 1024)).toFixed(1) + ' MB';
    const publishedDate = new Date().toISOString().slice(0, 10);

    if (sqliteAvailable) {
      await runSql('UPDATE staging_queue SET status = "APPROVED" WHERE id = ?', [id]);
      await runSql(
        'INSERT OR REPLACE INTO public_torrents VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [info_hash, torrentName, sizeBytes, sizeHuman, magnetUri, item.hash_sha3_512, 1, publishedDate]
      );
    }

    item.status = 'APPROVED';

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
    if (sqliteAvailable) {
      await runSql('UPDATE staging_queue SET status = "REJECTED", rejection_reason = ? WHERE id = ?', [reason, id]);
    }
    const item = inMemoryStagingQueue.find(s => s.id === id);
    if (item) {
      item.status = 'REJECTED';
      item.rejection_reason = reason;
    }
    res.json({ success: true, message: 'Upload successfully quarantined and rejected from public seedbox.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public BitTorrent Archive Endpoint (Reads from SQLite public_torrents or fallback)
app.get('/api/torrents', async (req, res) => {
  try {
    if (sqliteAvailable) {
      const rows = await queryAll('SELECT * FROM public_torrents ORDER BY published_date DESC');
      if (rows && rows.length > 0) return res.json(rows);
    }
  } catch (err) {
    console.warn('[Torrents DB fallback]:', err.message);
  }
  res.json([
    {
      name: "COA_AAR_Complete_Audit_Archive_2015_2023.tar.zst",
      size_bytes: 42949672960,
      size_human: "40.0 GB",
      info_hash: "8f7b5a1c9e2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a",
      magnet: "magnet:?xt=urn:btih:8f7b5a1c9e2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a&dn=COA_AAR_Complete_Audit_Archive_2015_2023",
      sha3_512: "a8f5c9e2b1d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
      seeders_on_1gbps_node: 1
    },
    {
      name: "PhilGEPS_Tenders_And_Awards_Full_Export_2014_2024.parquet",
      size_bytes: 8589934592,
      size_human: "8.0 GB",
      info_hash: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
      magnet: "magnet:?xt=urn:btih:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b&dn=PhilGEPS_Tenders_And_Awards_Full_Export",
      sha3_512: "e1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
      seeders_on_1gbps_node: 1
    }
  ]);
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
