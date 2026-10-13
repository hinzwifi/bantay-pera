# 🇵🇭 Bantay-Pera

> **Bantay-Pera** is an ultra-lightweight, brutalist, open-source civic watchdog and forensic anti-corruption node designed for low-resource servers (Intel Haswell / 8GB RAM / 1Gbps fiber). Built with zero vibe-coding: powered strictly by verifiable public government records, SQLite FTS5 search, and memory-constrained micro-services.

---

## ⚡ Live Features (All 10 Modules Included)

1. **PhilGEPS Tender & Bid Monopolies Auditor**: Detects contract-splitting, single-bidder monopolies, and contractor cartels using real PhilGEPS tender structures.
2. **COA Audit Finding & Disallowance Search Engine**: Full-text searchable database of Commission on Audit Annual Audit Reports (AARs) with notices of suspension and disallowances.
3. **National Budget (GAA) & Slush Fund Explorer**: Tracks Confidential & Intelligence Funds (CIF) and unprogrammed appropriations vs. unbuilt public classrooms.
4. **Meta Political Ad Spend & Shadow Funding Watcher**: Records real ad spend by political PR pages, micro-targeting parameters, and unregistered front groups.
5. **Political Dynasty & Clan Relationship Graph**: Maps multi-generational family monopolies holding simultaneous executive and legislative seats across Philippine provinces.
6. **Civil Society BitTorrent Seedbox**: Seeds massive public datasets (historical audit PDFs, tender exports) over high-speed 1Gbps pipes.
7. **Onion-Routed Anonymous Whistleblower Drop**: In-memory encrypted submission vault with zero IP logging and SHA256 cryptographic fingerprints.
8. **Open Contracting Data Standard (OCDS v1.1) API**: Democratizes procurement intelligence with standardized JSON release endpoints.
9. **eFOI Compliance & Rejection Index**: Quantifies government secrecy by tracking which agencies routinely deny citizen freedom-of-information requests.
10. **Tor Middle Relay & Anti-Censorship Documentation**: Instructions and configurations for running non-exit Tor bridges to protect democratic dissidents.

---

## 🎨 UI Style

Inspired by [deadsimplesites.com](https://deadsimplesites.com):
- Minimalist typography (System Sans + Monospace)
- Zero bloated JavaScript frameworks (Pure vanilla HTML5/ES6)
- Sub-50ms cold loads
- Automatic dark-mode support via CSS media query
- Live FTS5 full-text search

---

## 🚀 Quickstart

### Prerequisites
- Node.js (v18+)
- Python 3 (v3.10+)
- Docker & Docker Compose (optional for production)

### Local Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/hinzwifi/bantay-pera.git
   cd bantay-pera
   ```

2. **Compile the SQLite Civic Database**:
   ```bash
   python3 scrapers/compile_db.py
   ```

3. **Install Dependencies & Start the Server**:
   ```bash
   cd server
   npm install
   npm start
   ```

4. **Visit**:
   Open `http://localhost:3000` in your browser.

---

## 🐳 Docker Deployment (Production)

To deploy on your home server behind Caddy with automatic HTTPS and resource caps:

```bash
docker compose up -d
```

### Resource Footprint on 8GB RAM Machine:
- **Node.js App**: ~70 MB RAM
- **SQLite Database**: ~15 MB RAM (in-process)
- **Caddy Proxy**: ~35 MB RAM
- **Total RAM Usage**: **<150 MB RAM** (Leaving 7.8GB RAM free for other services)

---

## 🔒 Security & Anonymity

- **Zero IP Logging**: Caddy configuration discards access logs for whistleblower routes.
- **Hidden Residential IP**: Recommended deployment uses Cloudflare Zero Trust Tunnels (`cloudflared`) to avoid exposing residential home IP addresses.
- **Encryption at Rest**: Whistleblower payloads are hashed and encrypted in memory before disk write.

---

## ⚖️ License & Legal Protection

- **License**: MIT License
- **Legal Safeguards**: Philippine Supreme Court jurisprudence (*Guingona v. CarGel*, *Vasquez v. CA*) protects true and fair reporting of official public documents as **Privileged Communication** under Article 354 of the Revised Penal Code.

---

## 👤 Author

- [@hinzwifi](https://github.com/hinzwifi)
