"""IntelFusion dashboard — FastAPI app serving the 3D SOC dashboard + JSON API."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from engine.correlate import correlate, level_for, severity_for
from engine.fixtures import HOME_BASE, geo_for_ioc
from engine.store import Store

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"


def db_path() -> Path:
    return Path(os.environ.get("INTELFUSION_DB", ROOT / "data" / "intelfusion.db"))


def get_store() -> Store:
    return Store(db_path())


app = FastAPI(title="IntelFusion", version="1.0.0")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/api/feeds")
def api_feeds():
    store = get_store()
    try:
        runs = {r["feed"]: r for r in store.get_feed_runs()}
        counts = store.ioc_count_by_feed()
        feeds = []
        for feed in ("urlhaus", "otx", "abuseipdb", "demo-fixture"):
            run = runs.get(feed, {})
            feeds.append(
                {
                    "feed": feed,
                    "status": run.get("status", "never"),
                    "fetched_at": run.get("fetched_at"),
                    "ioc_count": counts.get(feed, 0),
                    "error": run.get("error"),
                }
            )
        return {"feeds": feeds}
    finally:
        store.close()


@app.get("/api/stats")
def api_stats():
    store = get_store()
    try:
        alerts = store.get_alerts(limit=10000)
        levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            levels[a["level"]] = levels.get(a["level"], 0) + 1
        counts = store.ioc_count_by_feed()
        return {
            "total_iocs": sum(counts.values()),
            "total_alerts": len(alerts),
            "by_level": levels,
        }
    finally:
        store.close()


@app.get("/api/alerts")
def api_alerts(limit: int = 100):
    store = get_store()
    try:
        return {"alerts": store.get_alerts(limit=min(limit, 500))}
    finally:
        store.close()


@app.get("/api/alerts/{alert_id}")
def api_alert_detail(alert_id: int):
    store = get_store()
    try:
        alert = store.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="alert not found")
        return alert
    finally:
        store.close()


@app.get("/api/iocs")
def api_iocs(limit: int = 200, q: str = ""):
    store = get_store()
    try:
        iocs = store.get_iocs()
        if q:
            ql = q.lower()
            iocs = [i for i in iocs if ql in i["value"].lower()]
        out = []
        for ioc in iocs[: min(limit, 1000)]:
            feeds = store.feeds_for_value(ioc["value"])
            score = severity_for(ioc["ioc_type"], feeds)
            out.append(
                {
                    "value": ioc["value"],
                    "ioc_type": ioc["ioc_type"],
                    "feeds": feeds,
                    "severity": score,
                    "level": level_for(score),
                    "first_seen": ioc["first_seen"],
                }
            )
        out.sort(key=lambda x: -x["severity"])
        return {"iocs": out, "total": len(iocs)}
    finally:
        store.close()


@app.get("/api/arcs")
def api_arcs(limit: int = 60):
    """Threat arcs for the 3D globe: attacker geo -> home base."""
    store = get_store()
    try:
        arcs = []
        seen: set[str] = set()
        for alert in store.get_alerts(limit=500):
            key = alert["ioc_value"]
            if key in seen:
                continue
            geo = geo_for_ioc(alert["ioc_value"], alert["ioc_type"])
            if not geo:
                continue
            seen.add(key)
            arcs.append(
                {
                    "from": {"lat": geo["lat"], "lon": geo["lon"],
                             "label": geo["country"]},
                    "to": {"lat": HOME_BASE["lat"], "lon": HOME_BASE["lon"],
                           "label": HOME_BASE["label"]},
                    "level": alert["level"],
                    "severity": alert["severity"],
                    "ioc": alert["ioc_value"],
                }
            )
            if len(arcs) >= limit:
                break
        return {"arcs": arcs, "home": HOME_BASE}
    finally:
        store.close()


@app.post("/api/scan")
def api_scan():
    """Trigger a correlation run over the demo logs. Returns new alert count."""
    logs = [
        ROOT / "demo" / "logs" / "auth.log",
        ROOT / "demo" / "logs" / "firewall.log",
    ]
    store = get_store()
    try:
        new_alerts = correlate(store, [p for p in logs if p.is_file()])
        return {"new_alerts": len(new_alerts), "alerts": new_alerts[:25]}
    finally:
        store.close()
