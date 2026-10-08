"""IntelFusion CLI.

    python -m engine --once --demo            # offline demo: fixtures + correlate
    python -m engine --once                   # live: fetch feeds + correlate
    python -m engine --interval 60            # live loop every 60 minutes

API keys via --config config.json or env vars OTX_API_KEY / ABUSEIPDB_API_KEY.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from .correlate import correlate
from .feeds import fetch_all
from .fixtures import DEMO_IOCS
from .iocs import make_ioc
from .store import Store

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("intelfusion")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "intelfusion.db"
DEFAULT_LOGS = [ROOT / "demo" / "logs" / "auth.log",
                ROOT / "demo" / "logs" / "firewall.log"]


def load_keys(config_path: str | None) -> tuple[str | None, str | None]:
    otx_key = os.environ.get("OTX_API_KEY")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    if config_path:
        try:
            cfg = json.loads(Path(config_path).read_text())
            otx_key = otx_key or cfg.get("otx_api_key")
            abuse_key = abuse_key or cfg.get("abuseipdb_api_key")
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("could not read config %s: %s", config_path, exc)
    return otx_key, abuse_key


def seed_fixtures(store: Store) -> int:
    iocs = [
        ioc for v, t in DEMO_IOCS
        if (ioc := make_ioc(v, "demo-fixture", t)) is not None
    ]
    n = store.upsert_iocs(iocs)
    log.info("seeded %d demo-fixture IOCs", n)
    return n


def run_pipeline(store: Store, args) -> list[dict]:
    # 1. feeds
    if args.demo:
        seed_fixtures(store)
        from datetime import datetime, timezone
        store.record_feed_run(
            "demo-fixture", datetime.now(timezone.utc).isoformat(),
            len(DEMO_IOCS), status="ok",
        )
    else:
        otx_key, abuse_key = load_keys(args.config)
        for result in fetch_all(otx_key, abuse_key):
            store.upsert_iocs(result.iocs)
            store.record_feed_run(
                result.feed, result.fetched_at, len(result.iocs),
                status=result.status, error=result.error,
            )
            log.info("feed %-10s -> %s (%d iocs)",
                     result.feed, result.status, len(result.iocs))

    # 2. correlate
    logs = [Path(p) for p in args.logs] if args.logs else DEFAULT_LOGS
    new_alerts = correlate(store, logs)

    # 3. JSON output
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(new_alerts, indent=2))
    log.info("wrote %d new alert(s) to %s", len(new_alerts), out_path)
    return new_alerts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="IntelFusion correlation engine")
    ap.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    ap.add_argument("--once", action="store_true", help="run pipeline once and exit")
    ap.add_argument("--interval", type=float, default=0,
                    help="loop every N minutes (0 = no loop)")
    ap.add_argument("--demo", action="store_true",
                    help="use synthetic fixture IOCs (fully offline)")
    ap.add_argument("--config", default=None, help="JSON file with API keys")
    ap.add_argument("--logs", nargs="*", default=None, help="log files to scan")
    ap.add_argument("--out", default=str(ROOT / "data" / "alerts.json"),
                    help="JSON file for new alerts")
    args = ap.parse_args(argv)

    if not args.once and args.interval <= 0:
        ap.error("choose --once or --interval MINUTES")

    store = Store(args.db)
    try:
        if args.interval > 0:
            log.info("starting scheduler loop every %.1f minute(s)", args.interval)
            while True:
                run_pipeline(store, args)
                time.sleep(args.interval * 60)
        else:
            new_alerts = run_pipeline(store, args)
            print(f"new alerts: {len(new_alerts)}")
    except KeyboardInterrupt:
        log.info("stopped by user")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
