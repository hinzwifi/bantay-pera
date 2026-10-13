#!/usr/bin/env python3
"""
Bantay-Pera Database Compiler & Anomaly Analyzer
Combines official public data sources into SQLite with full-text search (FTS5) and computed red flag metrics.
"""

import os
import json
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'bantay_pera.db')

def init_db():
    print(f"[*] Compiling database at: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 1. Procurement Table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS tenders (
        tender_id TEXT PRIMARY KEY,
        title TEXT,
        agency TEXT,
        location TEXT,
        abc_php REAL,
        awarded_php REAL,
        winning_bidder TEXT,
        registered_address TEXT,
        bidder_tin TEXT,
        bidders_count INTEGER,
        award_date TEXT,
        red_flags TEXT,
        notes TEXT,
        savings_php REAL,
        ratio_awarded_abc REAL
    )''')

    # 2. COA Audit Findings Table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS coa_findings (
        audit_id TEXT PRIMARY KEY,
        year INTEGER,
        agency TEXT,
        sector TEXT,
        opinion TEXT,
        flagged_amount_php REAL,
        finding_title TEXT,
        summary TEXT,
        pdf_reference TEXT,
        status TEXT
    )''')

    # 3. National Budget (GAA)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS national_budget (
        line_item_id TEXT PRIMARY KEY,
        fiscal_year INTEGER,
        department TEXT,
        agency TEXT,
        program_name TEXT,
        expense_class TEXT,
        amount_proposed_php REAL,
        amount_enacted_php REAL,
        status TEXT,
        classroom_equivalent INTEGER,
        description TEXT
    )''')

    # 4. Meta Ad Spend
    cur.execute('''
    CREATE TABLE IF NOT EXISTS meta_ads (
        campaign_id TEXT PRIMARY KEY,
        page_name TEXT,
        disclaimer TEXT,
        funder_tax_status TEXT,
        target_regions TEXT,
        target_gender TEXT,
        target_age TEXT,
        spend_php_estimate REAL,
        impressions_est TEXT,
        topic TEXT,
        narrative_template TEXT,
        creation_date TEXT,
        status TEXT
    )''')

    # 5. Political Dynasties
    cur.execute('''
    CREATE TABLE IF NOT EXISTS dynasties (
        dynasty_id TEXT PRIMARY KEY,
        clan_surname TEXT,
        home_province TEXT,
        years_in_power INTEGER,
        current_seats_held TEXT,
        monopoly_index TEXT,
        key_connected_contractors TEXT,
        notes TEXT
    )''')

    # 6. eFOI Compliance
    cur.execute('''
    CREATE TABLE IF NOT EXISTS efoi_agencies (
        agency_code TEXT PRIMARY KEY,
        agency_name TEXT,
        total_requests_2023 INTEGER,
        successful_granted INTEGER,
        denied_requests INTEGER,
        pending_or_ignored INTEGER,
        compliance_rate_percent REAL,
        most_common_denial_ground TEXT
    )''')

    # 7. Whistleblower Vault Table (Quantum-Resistant Hash Integrity)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS whistleblower_vault (
        submission_id TEXT PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        agency_targeted TEXT NOT NULL,
        description_digest TEXT NOT NULL,
        hash_sha3_512 TEXT NOT NULL,
        hash_blake2b TEXT NOT NULL,
        legacy_hash_sha256 TEXT NOT NULL,
        verification_status TEXT NOT NULL
    )''')

    # 8. Whistleblower Staging Quarantine Queue (Zero Public Seeding without Admin Audit)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS staging_queue (
        id TEXT PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        agency_targeted TEXT NOT NULL,
        public_note TEXT,
        file_name TEXT,
        file_size_bytes INTEGER DEFAULT 0,
        mime_type TEXT,
        status TEXT DEFAULT 'PENDING_REVIEW',
        rejection_reason TEXT,
        hash_sha3_512 TEXT NOT NULL,
        hash_blake2b TEXT NOT NULL,
        hash_sha256 TEXT NOT NULL,
        raw_payload_encrypted TEXT
    )''')

    # 9. Public BitTorrent Archive
    cur.execute('''
    CREATE TABLE IF NOT EXISTS public_torrents (
        info_hash TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        size_human TEXT NOT NULL,
        magnet TEXT NOT NULL,
        sha3_512 TEXT NOT NULL,
        seeders_on_1gbps_node INTEGER DEFAULT 1,
        published_date TEXT NOT NULL
    )''')

    # Full Text Search Virtual Tables (SQLite FTS5)
    cur.execute('''
    CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
        category,
        title,
        agency,
        snippet,
        identifier
    )''')

    conn.commit()
    return conn

def load_json(filename):
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def populate_data(conn):
    cur = conn.cursor()

    # Clear previous rows
    cur.execute("DELETE FROM tenders")
    cur.execute("DELETE FROM coa_findings")
    cur.execute("DELETE FROM national_budget")
    cur.execute("DELETE FROM meta_ads")
    cur.execute("DELETE FROM dynasties")
    cur.execute("DELETE FROM efoi_agencies")
    cur.execute("DELETE FROM search_index")

    # Ingest tenders
    tenders = load_json('procurement.json')
    for t in tenders:
        savings = t['abc_php'] - t['awarded_php']
        ratio = round((t['awarded_php'] / t['abc_php']) * 100, 2)
        cur.execute('''
        INSERT INTO tenders VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            t['tender_id'], t['title'], t['agency'], t['location'],
            t['abc_php'], t['awarded_php'], t['winning_bidder'],
            t['registered_address'], t['bidder_tin'], t['bidders_count'],
            t['award_date'], json.dumps(t['red_flags']), t['notes'],
            savings, ratio
        ))
        cur.execute("INSERT INTO search_index VALUES ('Procurement', ?, ?, ?, ?)",
                    (t['title'], t['agency'], t['notes'], t['tender_id']))

    # Ingest COA
    coas = load_json('coa_audits.json')
    for c in coas:
        cur.execute('''
        INSERT INTO coa_findings VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (
            c['audit_id'], c['year'], c['agency'], c['sector'],
            c['opinion'], c['flagged_amount_php'], c['finding_title'],
            c['summary'], c['pdf_reference'], c['status']
        ))
        cur.execute("INSERT INTO search_index VALUES ('COA Finding', ?, ?, ?, ?)",
                    (c['finding_title'], c['agency'], c['summary'], c['audit_id']))

    # Ingest GAA Budget
    budgets = load_json('national_budget.json')
    for b in budgets:
        cur.execute('''
        INSERT INTO national_budget VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            b['line_item_id'], b['fiscal_year'], b['department'], b['agency'],
            b['program_name'], b['expense_class'], b['amount_proposed_php'],
            b['amount_enacted_php'], b['status'], b['classroom_equivalent'],
            b['description']
        ))
        cur.execute("INSERT INTO search_index VALUES ('National Budget', ?, ?, ?, ?)",
                    (b['program_name'], b['department'], b['description'], b['line_item_id']))

    # Ingest Meta Ads
    ads = load_json('meta_ad_spend.json')
    for a in ads:
        cur.execute('''
        INSERT INTO meta_ads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            a['campaign_id'], a['page_name'], a['disclaimer'], a['funder_tax_status'],
            json.dumps(a['target_regions']), a['target_gender'], a['target_age'],
            a['spend_php_estimate'], a['impressions_est'], a['topic'],
            a['narrative_template'], a['creation_date'], a['status']
        ))
        cur.execute("INSERT INTO search_index VALUES ('Meta Ad Watch', ?, ?, ?, ?)",
                    (a['page_name'], a['disclaimer'], a['narrative_template'], a['campaign_id']))

    # Ingest Dynasties
    dyns = load_json('dynasties.json')
    for d in dyns:
        cur.execute('''
        INSERT INTO dynasties VALUES (?,?,?,?,?,?,?,?)
        ''', (
            d['dynasty_id'], d['clan_surname'], d['home_province'], d['years_in_power'],
            json.dumps(d['current_seats_held']), d['monopoly_index'],
            json.dumps(d['key_connected_contractors']), d['notes']
        ))
        cur.execute("INSERT INTO search_index VALUES ('Political Clan', ?, ?, ?, ?)",
                    (f"Clan {d['clan_surname']}", d['home_province'], d['notes'], d['dynasty_id']))

    # Ingest eFOI
    efois = load_json('efoi_compliance.json')
    for e in efois:
        cur.execute('''
        INSERT INTO efoi_agencies VALUES (?,?,?,?,?,?,?,?)
        ''', (
            e['agency_code'], e['agency_name'], e['total_requests_2023'],
            e['successful_granted'], e['denied_requests'], e['pending_or_ignored'],
            e['compliance_rate_percent'], e['most_common_denial_ground']
        ))
        cur.execute("INSERT INTO search_index VALUES ('eFOI Compliance', ?, ?, ?, ?)",
                    (e['agency_name'], e['agency_code'], e['most_common_denial_ground'], e['agency_code']))

    conn.commit()
    print("[+] Database successfully indexed and populated with genuine records.")

if __name__ == '__main__':
    conn = init_db()
    populate_data(conn)
    conn.close()
