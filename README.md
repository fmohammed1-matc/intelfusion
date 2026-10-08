# ◈ IntelFusion — Threat-Intelligence Correlation Engine

A lightweight, defensive **mini-SIEM**: IntelFusion pulls indicators of compromise
(IOCs) from public OSINT threat feeds, stores them in SQLite, and correlates
them against your local logs — raising severity-scored, deduplicated alerts
with full evidence. A cinematic 3D dashboard visualizes feed health, alerts,
and the global threat map in real time.

> **Defensive use only.** IntelFusion *reads* public blocklists and *analyzes*
> your own logs. It never scans, probes, attacks, or exploits anything.

## What it does

```
 ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
 │  URLhaus    │   │ AlienVault  │   │ AbuseIPDB   │
 │ (no key)    │   │ OTX (key)   │   │ (key)       │
 └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
        └─────────────────┼─────────────────┘
                          ▼
                 ┌─────────────────┐
                 │  Normalization  │  ipv4 · domain · url · sha256
                 │  → SQLite       │  feed source + first-seen
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐      ┌──────────────┐
                 │   Correlator    │◄─────│  auth.log /  │
                 │ score + dedupe  │      │ firewall.log │
                 └────────┬────────┘      └──────────────┘
                          ▼
                 ┌─────────────────┐      ┌──────────────┐
                 │  alerts.json    │─────►│ 3D Dashboard │
                 └─────────────────┘      │ (FastAPI +   │
                                          │  Three.js)   │
                                          └──────────────┘
```

- **Feed ingestion** — URLhaus works with no key; OTX and AbuseIPDB activate
  when API keys are configured (skipped gracefully otherwise, even offline).
- **Normalization** — every IOC is validated, canonicalized
  (lowercased domains/URLs, trimmed), and stored with its feed + first-seen time.
- **Correlation** — boundary-aware regex matching against log files, so
  `evil.example` matches `a.evil.example` but never `notevil.example`.
- **Scoring** — 0–100 severity from feed reputation + indicator fidelity
  (a SHA256 hit outranks an IP) + cross-feed corroboration bonus.
- **Deduplication** — the same IOC hitting the same log line alerts exactly once.
- **Dashboard** — dark SOC aesthetic, animated boot sequence, particle field,
  rotating 3D globe with animated threat arcs, feed-health cards, alert
  timeline, severity-ranked IOC table, and click-through alert evidence.

## Quickstart

```bash
# 1. Install
pip install -r requirements.txt

# 2. Generate demo logs (synthetic, fully offline)
python demo/generate_logs.py

# 3. Run the engine once in demo mode (fixture IOCs, no network needed)
python -m engine --once --demo

# 4. Launch the dashboard
uvicorn dashboard.main:app --port 8000
# open http://localhost:8000
```

Live mode (fetches real feeds) and scheduled runs:

```bash
python -m engine --once                          # fetch + correlate once
python -m engine --interval 60                   # repeat every 60 minutes
python -m engine --once --logs /var/log/auth.log # custom log files
```

## Adding API keys (optional)

URLhaus needs no key. For the other two feeds, either:

```bash
export OTX_API_KEY="your-alienvault-otx-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
```

or create `config.json`:

```json
{ "otx_api_key": "…", "abuseipdb_api_key": "…" }
```

then run with `--config config.json`. Feeds without keys are skipped gracefully —
the engine and dashboard keep working with whatever feeds are available.

## Project layout

```
intelfusion/
├── engine/            # correlation engine package
│   ├── iocs.py        # IOC model, validation, normalization
│   ├── feeds.py       # URLhaus / OTX / AbuseIPDB fetchers
│   ├── store.py       # SQLite persistence (IOCs, feed runs, alerts)
│   ├── correlate.py   # log matching, severity scoring, dedupe
│   ├── fixtures.py    # synthetic demo IOCs + demo geo mapping
│   └── __main__.py    # CLI: --once / --interval / --demo
├── dashboard/         # FastAPI app + 3D frontend
│   ├── main.py        # REST API (/api/feeds, /alerts, /iocs, /arcs, /scan)
│   └── static/        # index.html, style.css, app.js (Three.js globe)
├── demo/
│   └── generate_logs.py  # synthetic auth.log + firewall.log generator
├── tests/             # pytest suite (all network calls mocked)
├── data/              # runtime SQLite DB + alerts.json (git-ignored)
├── requirements.txt
└── LICENSE (MIT)
```

## API reference

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard UI |
| `GET /api/feeds` | Feed health: status, last fetch, IOC counts |
| `GET /api/stats` | Totals + alert counts by severity |
| `GET /api/alerts` | Alert list (newest first) |
| `GET /api/alerts/{id}` | Alert detail incl. matched log line |
| `GET /api/iocs?q=` | Severity-ranked IOC table, optional filter |
| `GET /api/arcs` | Threat arcs for the 3D globe |
| `POST /api/scan` | Trigger a correlation run, returns new alerts |

## Ethical note

IntelFusion is a **blue-team** tool. It consumes threat intelligence that
security vendors publish *for defenders*, and it analyzes logs you own.
Do not point it at systems or data you are not authorized to monitor, and
never use threat-intel tooling as a pretext for offensive activity.

## License

MIT — see [LICENSE](LICENSE).
