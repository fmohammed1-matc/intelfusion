"""Generate synthetic auth.log + firewall.log samples for the IntelFusion demo.

Plants hits for the fixture IOCs (engine/fixtures.py) inside realistic
benign noise. Everything is fake: documentation IP ranges, .example domains.
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.fixtures import DEMO_IOCS  # noqa: E402

BENIGN_USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
BENIGN_IPS = ["10.0.0.12", "10.0.0.15", "192.168.1.40", "172.16.0.9"]
BENIGN_DOMAINS = ["updates.ubuntu.example", "cdn.internal.example",
                  "mail.corp.example"]

SHA_FIXTURES = [v for v, t in DEMO_IOCS if t == "sha256"]
IP_FIXTURES = [v for v, t in DEMO_IOCS if t == "ipv4"]
DOMAIN_FIXTURES = [v for v, t in DEMO_IOCS if t == "domain"]
URL_FIXTURES = [v for v, t in DEMO_IOCS if t == "url"]


def _ts(rng: random.Random, base: datetime, i: int) -> str:
    return (base + timedelta(minutes=i * 3)).strftime("%b %d %H:%M:%S")


def gen_auth_log(rng: random.Random, base: datetime, hits: int) -> list[str]:
    lines: list[str] = []
    n = 120
    hit_at = set(rng.sample(range(n), hits))
    for i in range(n):
        ts = _ts(rng, base, i)
        if i in hit_at:
            ip = rng.choice(IP_FIXTURES)
            user = rng.choice(["root", "admin", "oracle"])
            lines.append(
                f"{ts} webserver sshd[{(1000 + i)}]: Failed password for "
                f"invalid user {user} from {ip} port {rng.randint(30000, 60000)} ssh2"
            )
        else:
            user = rng.choice(BENIGN_USERS)
            ip = rng.choice(BENIGN_IPS)
            ok = rng.random() < 0.7
            if ok:
                lines.append(
                    f"{ts} webserver sshd[{1000 + i}]: Accepted publickey for "
                    f"{user} from {ip} port {rng.randint(30000, 60000)} ssh2"
                )
            else:
                lines.append(
                    f"{ts} webserver sshd[{1000 + i}]: Failed password for "
                    f"{user} from {ip} port {rng.randint(30000, 60000)} ssh2"
                )
    return lines


def gen_firewall_log(rng: random.Random, base: datetime, hits: int) -> list[str]:
    lines: list[str] = []
    n = 120
    hit_at = set(rng.sample(range(n), hits))
    for i in range(n):
        ts = (base + timedelta(minutes=i * 3)).isoformat()
        if i in hit_at:
            kind = rng.choice(["url", "domain", "ip", "sha"])
            if kind == "url":
                detail = f"url={rng.choice(URL_FIXTURES)}"
            elif kind == "domain":
                detail = f"dns query {rng.choice(DOMAIN_FIXTURES)}"
            elif kind == "ip":
                detail = f"dst={rng.choice(IP_FIXTURES)}"
            else:
                detail = f"file hash {rng.choice(SHA_FIXTURES)}"
            lines.append(
                f"{ts} firewall kernel: DROP OUTBOUND {detail} "
                f"src=10.0.0.{rng.randint(2, 50)} action=blocked"
            )
        else:
            lines.append(
                f"{ts} firewall kernel: ALLOW OUTBOUND "
                f"dst={rng.choice(BENIGN_DOMAINS)} src=10.0.0.{rng.randint(2, 50)}"
            )
    return lines


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate IntelFusion demo logs")
    ap.add_argument("--out-dir", default="demo/logs")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--hits", type=int, default=14,
                    help="malicious hits per log file")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    base = datetime.now(timezone.utc) - timedelta(hours=6)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "auth.log").write_text("\n".join(gen_auth_log(rng, base, args.hits)) + "\n")
    (out / "firewall.log").write_text(
        "\n".join(gen_firewall_log(rng, base, args.hits)) + "\n"
    )
    print(f"wrote {out / 'auth.log'} and {out / 'firewall.log'} "
          f"({args.hits} planted hits each, seed={args.seed})")


if __name__ == "__main__":
    main()
